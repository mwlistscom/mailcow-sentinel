#!/usr/bin/env python3
"""
maildigest -- one short mail-server email per day: a verdict in the Subject,
then exceptions only.

It replaced a `pflogsumm` report that ran to **799 lines / 50 KB** every morning.
288 of those were a Warnings block in which **192 near-identical truncated lines
were a single credential-stuffing campaign** -- the most important thing in the
report, rendered so that it read as wallpaper.  Roughly 440 of the 799 lines were
per-sender and per-domain enumerations nobody reads on a phone at 6 a.m.

Design notes (why it is built this way):

  * Reads mailcow's Redis ring buffers, NOT `docker compose logs`.  Container
    logs reset whenever the container is recreated -- which is the documented
    procedure for changing postfix config -- so a log-based report silently
    covers a few hours and looks reassuringly quiet.  The rings survive restarts.
    Ring depth is still finite, so coverage is measured **per ring** and reported;
    the rings have different depths, and speaking for one by checking another is
    exactly the bug this is guarding against.

  * The window is a whole calendar day, not a rolling 24 h.  A rolling window
    straddles two dates, which makes day-over-day comparison impossible -- and
    day-over-day comparison is precisely what makes a spike visible.

  * Mails via `docker exec postfix sendmail -t`.  This needs no SMTP credentials
    at all, which is the point: the predecessor hardcoded a password in a
    world-readable file.

  * The verdict is computed in code.  The optional local LLM only classifies
    unfamiliar warning text; it never produces a number, and never blocks.

Usage:  maildigest.py [--date YYYY-MM-DD] [--stdout] [--no-llm]
                      [--html-out PATH] [--check-config] [--config PATH]
"""

import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict

import mcsentinel_common as mc

# Everything site-specific lives in config.ini -- see config.example.ini.
# CFG is populated in main() and read through the small accessors below, so the
# rest of the file never touches a hardcoded hostname, threshold or address.

CFG = {}

# ---------------------------------------------------------------- helpers

RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_ADDR = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+")
RE_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
RE_QID = re.compile(r"\b[0-9A-F]{8,14}\b")

RE_SASL_FAIL = re.compile(
    r"SASL (?:LOGIN|PLAIN|CRAM-MD5) authentication failed", re.I)
RE_SASL_OK = re.compile(r"sasl_method=\S+, sasl_username=(\S+)")
RE_CLIENT = re.compile(r"client=([^\[,]+)\[([\d.]+)\]")
RE_BRACKET_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
RE_USERNAME = re.compile(r"sasl_username=(\S+)")
RE_TO = re.compile(r"to=<([^>]*)>")
RE_RELAY = re.compile(r"relay=([^,]+)")
RE_DOVECOT_FAIL = re.compile(r"Password mismatch", re.I)
RE_DOVECOT_CTX = re.compile(r"lua\(([^,]+),([\d.]+)")

# A username that still carries a site URL glued to it is a line lifted from an
# infostealer log / combolist, where the URL+user+pass delimiter was eaten.
RE_COMBO = re.compile(
    r"(^https?[a-z0-9.-]*\.[a-z]{2,})|(^www\.[a-z0-9.-]+\.[a-z]{2,}[a-z])", re.I)


def normalise(msg):
    """Collapse a log message to a stable 'class' so it can be diffed day to day."""
    s = RE_IP.sub("<IP>", msg)
    s = RE_ADDR.sub("<ADDR>", s)
    s = RE_QID.sub("<QID>", s)
    s = RE_HOST.sub("<HOST>", s)
    s = re.sub(r"\[\d+\]", "[<PID>]", s)
    s = re.sub(r"\b\d+\b", "<N>", s)
    return re.sub(r"\s+", " ", s).strip()[:180]


# Generic labels that carry no identity: the recognisable part of a DNSBL zone
# is whatever is left once these are removed. bl.spamcop.net -> spamcop,
# hostkarma.junkemailfilter.com -> hostkarma, zen.dq.spamhaus.net -> spamhaus zen.
_ZONE_NOISE = {"bl", "b", "dnsbl", "rbl", "wl", "list", "dq", "net", "com",
               "org", "sbl", "xbl", "pbl", "dbl", "zrd"}


def short_zone(zone):
    parts = [p for p in zone.lower().split(".") if p]
    if "spamhaus" in parts:
        flavour = next((p for p in parts if p in ("zen", "dbl", "zrd")), "")
        return f"spamhaus {flavour}".strip()
    for p in parts:
        if p not in _ZONE_NOISE:
            return p
    return zone


def pct(n, d):
    return 0.0 if not d else round(100.0 * n / d, 1)


# ---------------------------------------------------------------- collection

def collect(mcw, day_start, day_end):
    """Walk the rings once and build every number the digest needs."""
    m = {
        "received": 0, "delivered": 0, "local": 0, "external": 0,
        "deferred": 0, "bounced": 0, "rejected": 0,
        "greylisted": 0, "hard_reject": 0,
        "recv_by": Counter(), "sent_by": Counter(),
        "auth_fail": 0, "auth_ips": set(), "auth_targets": Counter(),
        "auth_ips_count": Counter(),
        "combo_users": Counter(),
        "auth_ok": [], "auth_ok_unexpected": [], "auth_ok_external_known": [],
        "dovecot_fail": 0, "dovecot_ips": set(), "dovecot_targets": Counter(),
        "warn_classes": Counter(), "warn_example": {},
        "bans": 0, "ban_ips": set(),
        "reject_reasons": Counter(),
        "connects": 0, "conn_ips": set(), "probes": 0, "tls_fail": 0,
        "auth_drop": 0, "allowlisted": 0,
        "dnsbl": Counter(), "dnsbl_ips": set(),
        "lines": 0,
    }

    # Ring coverage is tracked inside Mailcow.ring() per key, and read back via
    # mcw.coverage(); it is deliberately not derived from one ring here.
    for ts, prog, msg in mcw.ring("POSTFIX_MAILLOG"):
        if not (day_start <= ts < day_end):
            continue
        m["lines"] += 1

        # ---- flow
        if "message-id=" in msg and "cleanup" in prog:
            m["received"] += 1
        if "status=sent" in msg:
            m["delivered"] += 1
            relay = RE_RELAY.search(msg)
            is_local = relay and "dovecot" in relay.group(1)
            if is_local:
                m["local"] += 1
                to = RE_TO.search(msg)
                if to and to.group(1):
                    m["recv_by"][to.group(1).lower()] += 1
            else:
                m["external"] += 1
        elif "status=deferred" in msg:
            m["deferred"] += 1
        elif "status=bounced" in msg:
            m["bounced"] += 1

        if "reject:" in msg:
            m["rejected"] += 1
            if re.search(r"\b4\.\d\.\d\b", msg):
                m["greylisted"] += 1
            else:
                m["hard_reject"] += 1
            reason = "unknown"
            # Skip a bracketed address between the status code and the text:
            # `450 4.7.1 <user@host>: Sender address rejected: ...` would
            # otherwise report the address itself as the reason -- noise, and it
            # drags a recipient address into the summary.
            rm = re.search(
                r"\b[45]\.\d\.\d\s+(?:<[^>]*>:?\s*)?([^;]{0,60})", msg)
            if rm:
                reason = rm.group(1).strip()
            elif "blocked using" in msg:
                rm = re.search(r"blocked using (\S+)", msg)
                reason = "DNSBL " + rm.group(1) if rm else "DNSBL"
            m["reject_reasons"][reason[:58]] += 1

        # ---- authentication
        if RE_SASL_FAIL.search(msg):
            m["auth_fail"] += 1
            ip = RE_BRACKET_IP.search(msg)
            if ip:
                m["auth_ips"].add(ip.group(1))
                m["auth_ips_count"][ip.group(1)] += 1
            u = RE_USERNAME.search(msg)
            if u:
                user = u.group(1)
                m["auth_targets"][user] += 1
                if RE_COMBO.search(user):
                    m["combo_users"][user] += 1
        ok = RE_SASL_OK.search(msg)
        if ok:
            user = ok.group(1)
            cl = RE_CLIENT.search(msg)
            hostpart, ip = (cl.group(1), cl.group(2)) if cl else ("?", "?")
            rec = (user, hostpart, ip)
            m["auth_ok"].append(rec)
            internal = mc.in_networks(ip, CFG["trusted_auth"])
            allowed = any(user.lower() == u and h in hostpart.lower()
                          for u, h in CFG["auth_allow"])
            if not internal and not allowed:
                m["auth_ok_unexpected"].append(rec)
            elif allowed:
                m["auth_ok_external_known"].append(rec)
            m["sent_by"][user.lower()] += 1

        # ---- what is knocking on the door, vs what becomes mail
        if msg.startswith("connect from"):
            m["connects"] += 1
            g = RE_BRACKET_IP.search(msg)
            if g:
                m["conn_ips"].add(g.group(1))
        elif "lost connection after CONNECT" in msg:
            m["probes"] += 1
        elif "lost connection after AUTH" in msg:
            m["auth_drop"] += 1
        elif "SSL_accept error" in msg:
            m["tls_fail"] += 1
        elif msg.startswith("ALLOWLISTED"):
            m["allowlisted"] += 1
        elif "listed by domain" in msg:
            z = re.search(r"listed by domain (\S+)", msg)
            ip = RE_IP.search(msg)
            if z:
                # Strip a DQS key prefix. Spamhaus DQS zones are
                # <key>.zen.dq.spamhaus.net -- the key is a credential and must
                # never reach the digest, which is emailed and may be forwarded.
                zone = re.sub(r"^[A-Za-z0-9]{16,}\.", "", z.group(1))
                m["dnsbl"][zone] += 1
            if ip:
                m["dnsbl_ips"].add(ip.group(0))

        # ---- warnings (SASL noise excluded; it is summarised above)
        if msg.startswith("warning:") and "SASL" not in msg:
            cls = normalise(msg)
            m["warn_classes"][cls] += 1
            m["warn_example"].setdefault(cls, msg[:150])

    for ts, _prog, msg in mcw.ring("DOVECOT_MAILLOG"):
        if not (day_start <= ts < day_end):
            continue
        if RE_DOVECOT_FAIL.search(msg):
            ctx = RE_DOVECOT_CTX.search(msg)
            if ctx and ctx.group(1) in CFG["ignore_users"]:
                continue
            m["dovecot_fail"] += 1
            if ctx:
                m["dovecot_targets"][ctx.group(1)] += 1
                m["dovecot_ips"].add(ctx.group(2))
                m["auth_ips_count"][ctx.group(2)] += 1
                if RE_COMBO.search(ctx.group(1)):
                    m["combo_users"][ctx.group(1)] += 1

    for ts, _prog, msg in mcw.ring("NETFILTER_LOG"):
        if not (day_start <= ts < day_end):
            continue
        if "Banning" in msg and "Unbanning" not in msg:
            m["bans"] += 1
            ip = RE_IP.search(msg)
            if ip:
                m["ban_ips"].add(ip.group(0))

    return m


def system_state(mcw):
    s = {"containers": 0, "unhealthy": [], "queue": 0, "cert_days": None}
    # Filtered by compose label, not by a name substring: a substring match on
    # the project name would also count unrelated sidecars a user happens to
    # have named similarly.
    s["containers"] = mcw.container_count()
    s["unhealthy"] = mcw.unhealthy()

    q = mc.sh(["docker", "exec", mcw.container("postfix-mailcow"),
               "postqueue", "-p"])
    if "Mail queue is empty" in q:
        s["queue"] = 0
    else:
        s["queue"] = len(re.findall(r"^[0-9A-F]{8,}", q, re.M))

    end = mc.sh(["openssl", "x509", "-in", mcw.cert_path, "-noout", "-enddate"])
    if end.startswith("notAfter="):
        try:
            exp = dt.datetime.strptime(
                end.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=dt.timezone.utc)
            s["cert_days"] = (exp - dt.datetime.now(dt.timezone.utc)).days
        except ValueError:
            pass
    return s


# ---------------------------------------------------------------- history

def db_save(c, date_s, m):
    # One explicit BEGIN IMMEDIATE around the whole write: with sqlite3's
    # default deferred transactions a read-then-write can hit SQLITE_BUSY on the
    # upgrade, and the busy handler cannot retry that case at all.
    c.execute("BEGIN IMMEDIATE")
    accounts = set(m["recv_by"]) | set(m["sent_by"])
    for a in accounts:
        c.execute("INSERT OR REPLACE INTO account_day VALUES (?,?,?,?)",
                  (date_s, a, m["recv_by"][a], m["sent_by"][a]))
    slim = {k: v for k, v in m.items()
            if isinstance(v, (int, float, str)) or v is None}
    c.execute("INSERT OR REPLACE INTO daily VALUES (?,?)",
              (date_s, json.dumps(slim)))
    for cls, n in m["warn_classes"].items():
        row = c.execute("SELECT total FROM warn_class WHERE cls=?",
                        (cls,)).fetchone()
        if row:
            c.execute("UPDATE warn_class SET last_seen=?, total=? WHERE cls=?",
                      (date_s, row[0] + n, cls))
        else:
            c.execute("INSERT INTO warn_class VALUES (?,?,?,?)",
                      (cls, date_s, date_s, n))
    mc.meta_set(c, "digest_last_run", int(dt.datetime.now().timestamp()))
    c.execute("COMMIT")


def db_history_days(c, date_s):
    """How many earlier days are already recorded."""
    return c.execute("SELECT COUNT(*) FROM daily WHERE date < ?",
                     (date_s,)).fetchone()[0]


def db_new_classes(c, date_s, m, lookback=7):
    """Warning classes seen today but not in the previous `lookback` days.

    Returns [] until there is at least a day of history -- on a cold database
    every class is 'new', which would bury the real signal on the first run.
    """
    if db_history_days(c, date_s) < 1:
        return []
    start = (dt.date.fromisoformat(date_s) -
             dt.timedelta(days=lookback)).isoformat()
    known = {r[0] for r in c.execute(
        "SELECT cls FROM warn_class WHERE first_seen < ? AND last_seen >= ?",
        (date_s, start))}
    return [(cls, n) for cls, n in m["warn_classes"].most_common()
            if cls not in known]


def db_baseline(c, date_s, days=7):
    """Mean recv/sent per account over the `days` before date_s."""
    start = (dt.date.fromisoformat(date_s) - dt.timedelta(days=days)).isoformat()
    out = {}
    for acct, r, s, n in c.execute(
            "SELECT account, AVG(recv), AVG(sent), COUNT(*) FROM account_day "
            "WHERE date >= ? AND date < ? GROUP BY account", (start, date_s)):
        out[acct] = {"recv": r or 0.0, "sent": s or 0.0, "n": n}
    return out


def db_bans(c, day_start, day_end):
    """What authguard's denylist did on this day, plus what it currently holds.

    Reads the ledger authguard maintains in the same history.db. If authguard is
    not installed the tables are still created by the shared schema, so this
    simply reports zeros rather than failing.
    """
    q = c.execute
    live = q("SELECT COUNT(*) FROM authguard_ban").fetchone()[0]
    added = q("SELECT COUNT(*) FROM authguard_ban WHERE added_ts >= ? AND added_ts < ?",
              (day_start, day_end)).fetchone()[0]
    reasons = q("SELECT reason, COUNT(*) FROM authguard_ban "
                "WHERE added_ts >= ? AND added_ts < ? GROUP BY reason "
                "ORDER BY 2 DESC", (day_start, day_end)).fetchall()
    expiring = q("SELECT COUNT(*) FROM authguard_ban WHERE expires_ts < ?",
                 (day_end + 86400,)).fetchone()[0]
    oldest = q("SELECT MIN(added_ts) FROM authguard_ban").fetchone()[0]
    return {"live": live, "added": added, "reasons": reasons,
            "expiring": expiring, "oldest": oldest}


def db_series(c, date_s, days=30):
    """Per-day totals per account, oldest first, for the chart.

    Windowed on the report date rather than today, so `--date` backfill charts
    the days it is actually reporting on.
    """
    end = dt.date.fromisoformat(date_s)
    start = (end - dt.timedelta(days=days)).isoformat()
    rows = c.execute(
        "SELECT date, account, recv, sent FROM account_day "
        "WHERE date >= ? AND date <= ? ORDER BY date",
        (start, date_s)).fetchall()
    series = defaultdict(lambda: defaultdict(lambda: {"recv": 0, "sent": 0}))
    for d, a, r, s in rows:
        series[d][a] = {"recv": r, "sent": s}
    return series


# ---------------------------------------------------------------- verdict

def verdict(m, st, baseline, new_classes, expected_containers):
    """Deterministic.  Returns (level, [reasons]).  The LLM never decides this."""
    reasons = []
    level = "OK"

    def bump(to, why):
        nonlocal level
        order = {"OK": 0, "ATTENTION": 1, "CRITICAL": 2}
        if order[to] > order[level]:
            level = to
        reasons.append(why)

    if m["auth_ok_unexpected"]:
        who = ", ".join(sorted({f"{u} from {ip}"
                                for u, _, ip in m["auth_ok_unexpected"]}))
        bump("CRITICAL", f"login from an unrecognised source ({who})")
    if st["unhealthy"]:
        bump("CRITICAL", f"{len(st['unhealthy'])} container(s) unhealthy")
    if (expected_containers and st["containers"]
            and st["containers"] < expected_containers):
        bump("CRITICAL",
             f"only {st['containers']}/{expected_containers} containers up")

    for acct, n in m["sent_by"].items():
        base = baseline.get(acct, {}).get("sent", 0.0)
        if n >= CFG["th_sent_spike"] and n > max(3 * base, 10):
            bump("CRITICAL", f"{acct} sent {n} messages (baseline {base:.0f})")

    if m["auth_fail"] + m["dovecot_fail"] >= CFG["th_auth_fail"]:
        tgt = ", ".join(f"{u.split('@')[0]}@" for u, _ in
                        m["auth_targets"].most_common(3))
        bump("ATTENTION",
             f"credential stuffing vs {tgt or 'mailboxes'}")
    if m["combo_users"]:
        bump("ATTENTION", "breach-dump usernames in use against this server")
    if m["bounced"]:
        bump("ATTENTION", f"{m['bounced']} bounced")
    if m["deferred"] >= CFG["th_deferred"]:
        bump("ATTENTION", f"{m['deferred']} deferred")
    if st["queue"] >= CFG["th_queue"]:
        bump("ATTENTION", f"{st['queue']} messages queued")
    if st["cert_days"] is not None and st["cert_days"] <= CFG["th_cert_days"]:
        bump("ATTENTION", f"certificate expires in {st['cert_days']} days")
    if new_classes:
        reasons.append(f"{len(new_classes)} new warning class(es)")

    return level, reasons


# ---------------------------------------------------------------- local LLM

def llm_triage(new_classes, examples):
    if not new_classes:
        return None
    lines = []
    for cls, n in new_classes[:12]:
        lines.append(f"{n}x  {examples.get(cls, cls)[:120]}")
    prompt = (CFG["llm_prompt"]
              + f"\n\nWarning classes seen today but not in the previous "
                f"{CFG['baseline_days']} days:\n\n" + "\n".join(lines) + "\n")
    body = json.dumps({
        "model": CFG["llm_model"], "prompt": prompt, "stream": False,
        "think": False,
        "options": {"temperature": 0.2, "num_predict": 350},
    }).encode()
    req = urllib.request.Request(
        CFG["llm_url"], data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=CFG["llm_timeout"]) as r:
            return json.load(r).get("response", "").strip() or None
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


# ---------------------------------------------------------------- rendering

def bar(n, scale, width=18):
    if scale <= 0:
        return ""
    return "#" * max(1, int(round(n / scale * width))) if n else ""


def render_text(date_s, m, st, baseline, new_classes, llm, coverage, hist_days,
                bans=None):
    L = []
    add = L.append
    # Sent is weighted heavily: an account that sent anything is more
    # interesting than one that merely received. Name breaks ties so the
    # ordering is stable run to run.
    mail_accounts = sorted(
        set(m["recv_by"]) | set(m["sent_by"]),
        key=lambda a: (-(m["recv_by"][a] + m["sent_by"][a] * 5), a))

    add(f"FLOW        {m['received']} received - {m['delivered']} delivered "
        f"- {m['external']} sent externally")
    add(f"            {m['deferred']} deferred - {m['bounced']} bounced "
        f"- {m['rejected']} rejected "
        f"({m['greylisted']} greylist, {m['hard_reject']} hard)")
    add(f"            queue {st['queue']} - containers "
        f"{st['containers']}/{CFG['expected_containers']}"
        + (f" - cert {st['cert_days']}d" if st["cert_days"] is not None else ""))
    add("")

    if mail_accounts:
        add(f"ACCOUNTS            recv  sent   vs {CFG['baseline_days']}-day")
        peak = max([m["recv_by"][a] for a in mail_accounts] + [1])
        for a in mail_accounts[:12]:
            r, s = m["recv_by"][a], m["sent_by"][a]
            b = baseline.get(a)
            if b and b["n"] >= 3 and b["recv"] >= 1:
                d = pct(r - b["recv"], b["recv"])
                delta = f"{d:+.0f}%"
            else:
                delta = "  --"
            name = a if len(a) <= 18 else a[:17] + "~"
            add(f"  {name:<18}{r:>4} {s:>5}   {delta:>6}  {bar(r, peak)}")
        add("")

    total_fail = m["auth_fail"] + m["dovecot_fail"]
    if total_fail:
        ips = len(m["auth_ips"] | m["dovecot_ips"])
        tag = "! AUTH" if total_fail >= CFG["th_auth_fail"] else "  auth"
        add(f"{tag}      {total_fail} failures ({m['auth_fail']} smtp, "
            f"{m['dovecot_fail']} imap) - {ips} IPs - {m['bans']} banned "
            f"({pct(m['bans'], total_fail):.0f}%)")
        tgts = (m["auth_targets"] + m["dovecot_targets"]).most_common(4)
        if tgts:
            add("            targets: " +
                " - ".join(f"{u} {n}" for u, n in tgts))
        if m["combo_users"]:
            add(f"            {sum(m['combo_users'].values())} attempts used "
                f"breach-dump usernames, e.g.")
            for u, _ in m["combo_users"].most_common(3):
                add(f"              {u}")
            add("            -> these addresses are in a public combolist;")
            add("               check those mailbox passwords are not reused")
        add("")

    if m["auth_ok_unexpected"]:
        add("! LOGIN     authenticated send from an unrecognised source:")
        for u, h, ip in m["auth_ok_unexpected"][:5]:
            add(f"              {u} from {h}[{ip}]")
        add("")

    if bans and (bans["live"] or bans["added"]):
        why = ", ".join(f"{r} {n}" for r, n in bans["reasons"]) or "none today"
        add(f"BLOCKED     {bans['added']} added today - {bans['live']} denylisted now"
            f" - {bans['expiring']} expiring within 24h")
        add(f"            added by: {why}")
        if m["bans"]:
            add(f"            netfilter's own rule banned {m['bans']} separately")
        add("")

    if m["connects"]:
        att = len(m["auth_ips"] | m["dovecot_ips"])
        yielded = pct(m["received"], m["connects"])
        add(f"FRONT DOOR  {m['connects']} connections from {len(m['conn_ips'])} "
            f"IPs -> {m['received']} messages ({yielded:.0f}% yielded mail)")
        add(f"            {m['probes']} connected and vanished - "
            f"{m['tls_fail']} failed TLS - {m['auth_drop']} abandoned mid-auth")
        add(f"            {att} IPs tried to authenticate"
            + (f" - {bans['added']} of them banned" if bans and bans["added"] else ""))
        worst = (m["auth_ips_count"].most_common(3)
                 if m.get("auth_ips_count") else [])
        if worst:
            add("            worst: " + " - ".join(f"{ip} ({n})" for ip, n in worst))
        add("")

    if m["dnsbl"]:
        wl = {z: n for z, n in m["dnsbl"].items() if "dnswl" in z or z.startswith("wl.")}
        bl = {z: n for z, n in m["dnsbl"].items() if z not in wl}
        if bl:
            add(f"BLOCKLISTS  {len(m['dnsbl_ips'])} IPs listed - "
                + ", ".join(f"{short_zone(z)} {n}"
                            for z, n in sorted(bl.items(), key=lambda x: -x[1])[:6]))
        if wl:
            add("            allowlisted: "
                + ", ".join(f"{short_zone(z)} {n}"
                            for z, n in sorted(wl.items(), key=lambda x: -x[1])))
        add("")

    if m["reject_reasons"] and m["hard_reject"]:
        add("REJECTS     " + "; ".join(
            f"{r} ({n})" for r, n in m["reject_reasons"].most_common(3)))
        add("")

    if new_classes:
        add(f"NEW         {len(new_classes)} warning class(es) not seen in the "
            f"previous 7 days:")
        for cls, n in new_classes[:6]:
            add(f"              {n}x {m['warn_example'].get(cls, cls)[:88]}")
        add("")

    if llm:
        add(f"TRIAGE      ({CFG['llm_model']}, advisory - classification only)")
        seen = Counter(l.strip()[:92] for l in llm.splitlines() if l.strip())
        for line, n in seen.most_common(12):
            add(f"              {line}" + (f"   (x{n})" if n > 1 else ""))
        add("")

    ok = []
    if not m["auth_ok_unexpected"]:
        ok.append("no unexplained logins")
    if not m["bounced"] and not m["deferred"]:
        ok.append("no delivery failures")
    if not st["unhealthy"] and st["containers"] >= CFG["expected_containers"]:
        ok.append(f"{st['containers']}/{CFG['expected_containers']} containers up")
    if ok:
        add("OK          " + " - ".join(ok))
        for u, h, ip in sorted(set(m["auth_ok_external_known"])):
            add(f"            expected external sender: {u} via {h}[{ip}]")
        add("")

    if hist_days < 7:
        add(f"BASELINE    building - {hist_days}/7 days recorded. "
            f"Per-account deltas and new-warning detection")
        add("            start once there is a week of history.")
        add("")

    short = {k: v for k, v in coverage.items() if not v["full"]}
    if short:
        add("! COVERAGE  a log ring did not reach back to the start of the day;")
        add("            the counts above are LOW, not reassuring:")
        for key, v in sorted(short.items()):
            add(f"              {key:<18} missing the first "
                f"{v['missing_hours']:.1f}h  ({v['entries']} entries held)")
        add("            mailcow's rings are fixed-size, and a chatty service")
        add("            rolls its ring sooner than a quiet one.")
        add("")

    add(f"-- {m['lines']} log lines from the Redis rings, "
        f"{date_s}. Chart attached.")
    return "\n".join(L)


def render_html(date_s, m, series, level):
    """Self-contained chart page, attached to the mail."""
    S1, S2 = "#2a78d6", "#eb6834"
    days = sorted(series)
    accounts = sorted({a for d in days for a in series[d]})
    # Scale on BOTH series. Peaking on recv alone means a compromised mailbox --
    # the one case this chart exists to reveal -- renders its sent bar far taller
    # than the plot, overflowing the card instead of standing out in it.
    peak = max([max(v["recv"], v["sent"])
                for d in days for v in series[d].values()] + [1])

    rows = []
    for a in accounts:
        cells = []
        for d in days:
            v = series[d].get(a, {"recv": 0, "sent": 0})
            # Floor of 3px, not 1px: a single message scaled against a peak
            # of hundreds renders as a hairline that reads as zero. Outbound is
            # the compromise tripwire, and the whole value of a near-zero
            # baseline is that ANY outbound is visible -- so a nonzero value
            # must look nonzero. Zero still draws nothing.
            h = max(3, int(v["recv"] / peak * 46)) if v["recv"] else 0
            sh_ = max(3, int(v["sent"] / peak * 46)) if v["sent"] else 0
            cells.append(
                f'<div class="col" title="{html.escape(d)} &middot; '
                f'{html.escape(a)}&#10;recv {v["recv"]} / sent {v["sent"]}">'
                f'<span class="r" style="height:{h}px"></span>'
                + (f'<span class="s" style="height:{sh_}px"></span>' if sh_ else "")
                + "</div>")
        tot_r = sum(series[d].get(a, {}).get("recv", 0) for d in days)
        tot_s = sum(series[d].get(a, {}).get("sent", 0) for d in days)
        rows.append(
            f'<section><h2>{html.escape(a)}<em>{tot_r} recv &middot; '
            f'{tot_s} sent</em></h2><div class="plot">'
            + "".join(cells) + "</div></section>")

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{CFG["hostname"]} &mdash; {date_s}</title><style>
:root{{color-scheme:light dark;--bg:#f4f6f9;--card:#fff;--ink:#101520;
--dim:#666f7e;--rule:#dfe4ec;--s1:{S1};--s2:{S2}}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0c0f14;--card:#151a22;
--ink:#f1f4f9;--dim:#98a1b1;--rule:#262d38;--s1:#3987e5;--s2:#d95926}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);padding:28px 18px 60px;
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
.wrap{{max-width:900px;margin:0 auto}}
h1{{font-size:1.5rem;margin:0 0 4px;letter-spacing:-.02em}}
.sub{{color:var(--dim);font-size:.86rem;margin-bottom:22px}}
.lg{{display:flex;font-size:.8rem;color:var(--dim);margin-bottom:18px}}
.lg span{{margin-right:16px}}
.lg i{{display:inline-block;width:10px;height:10px;border-radius:2px;
margin-right:5px;vertical-align:-1px}}
section{{background:var(--card);border:1px solid var(--rule);border-radius:10px;
padding:14px 16px;margin-bottom:10px}}
h2{{font-size:.9rem;font-weight:600;margin:0 0 10px;display:flex;
justify-content:space-between;align-items:baseline}}
h2 em{{font-style:normal;font-weight:400;color:var(--dim);font-size:.78rem}}
.plot{{display:flex;align-items:flex-end;height:52px;
border-bottom:1px solid var(--rule);overflow-x:auto}}
.col{{display:flex;flex-direction:column-reverse;justify-content:flex-start;
min-width:7px;flex:1;margin-right:2px}}
.col:last-child{{margin-right:0}}
.col .s{{margin-bottom:1px}}
.r{{background:var(--s1);border-radius:2px 2px 0 0;display:block}}
.s{{background:var(--s2);border-radius:2px 2px 0 0;display:block}}
footer{{color:var(--dim);font-size:.78rem;margin-top:20px}}
</style></head><body><div class="wrap">
<h1>{CFG["hostname"]} &mdash; {level}</h1>
<div class="sub">Daily mail volume per mailbox &middot; {len(days)} day(s)
through {date_s}. Hover a bar for exact counts.</div>
<div class="lg"><span><i style="background:var(--s1)"></i>Received</span>
<span><i style="background:var(--s2)"></i>Sent externally</span></div>
{"".join(rows) or "<section>No history yet &mdash; this is the first run.</section>"}
<footer>Sent externally is the compromise tripwire: this server's baseline is
near zero, so any sustained orange is worth opening immediately.</footer>
</div></body></html>"""


# ------------------------------------------------------- html mail body

# Palette: the light set, contrast-checked against the card background. Mail
# clients cannot be relied on for prefers-color-scheme, and a half-applied dark
# theme is worse than a committed light one, so this is light and explicit.
P = {"plane": "#f4f6f9", "card": "#ffffff", "rule": "#e2e6ed",
     "ink": "#1f2430", "dim": "#67717f", "bad": "#b3261e", "good": "#0f7b2f",
     "warn": "#8a5a00", "key": "#1f5fa8", "s1": "#2a78d6", "s2": "#eb6834"}
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"
SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"


def _card(label, colour, body):
    """One titled card. Tables, not divs: Outlook ignores most box models."""
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-collapse:separate;margin:0 0 10px"><tr>'
        f'<td style="background:{P["card"]};border:1px solid {P["rule"]};'
        f'border-left:3px solid {colour};border-radius:8px;padding:13px 16px">'
        f'<div style="font:600 11px/1.4 {SANS};letter-spacing:.09em;'
        f'text-transform:uppercase;color:{colour};padding-bottom:7px">{label}</div>'
        f'{body}</td></tr></table>')


def _mono(txt, colour=None, size="13px"):
    return (f'<div style="font:400 {size}/1.65 {MONO};color:{colour or P["ink"]};'
            f'white-space:normal">{txt}</div>')


def render_email_html(date_s, m, st, baseline, new_classes, llm, coverage,
                      hist_days, bans, level, reasons):
    e = html.escape
    accent = P["good"] if level == "OK" else P["bad"]
    out = []

    # ---- header
    out.append(
        f'<div style="font:600 11px/1.4 {SANS};letter-spacing:.1em;'
        f'text-transform:uppercase;color:{P["dim"]}">'
        f'{e(CFG["hostname"])} &middot; {e(date_s)}</div>'
        f'<div style="font:700 26px/1.2 {SANS};color:{accent};padding:4px 0 2px">'
        f'{e(level)}</div>'
        f'<div style="font:400 14px/1.55 {SANS};color:{P["ink"]};padding-bottom:18px">'
        f'{e("; ".join(reasons) if reasons else "nothing unusual")}</div>')

    # ---- flow, as figures rather than a sentence
    cells = [("received", m["received"], P["ink"]),
             ("delivered", m["delivered"], P["ink"]),
             ("sent out", m["external"], P["ink"]),
             ("deferred", m["deferred"], P["bad"] if m["deferred"] else P["ink"]),
             ("bounced", m["bounced"], P["bad"] if m["bounced"] else P["ink"]),
             ("rejected", m["rejected"], P["ink"])]
    tds = "".join(
        f'<td style="padding:0 14px 0 0;vertical-align:top">'
        f'<div style="font:700 20px/1.1 {SANS};color:{c}">{v}</div>'
        f'<div style="font:400 11px/1.4 {SANS};color:{P["dim"]}">{k}</div></td>'
        for k, v, c in cells)
    sub = (f'queue {st["queue"]} &middot; containers {st["containers"]}/'
           f'{CFG["expected_containers"]}')
    if st["cert_days"] is not None:
        sub += f' &middot; cert {st["cert_days"]}d'
    sub += (f' &middot; {m["greylisted"]} greylisted, {m["hard_reject"]} hard-rejected')
    out.append(_card("Flow", P["key"],
                     f'<table role="presentation" cellpadding="0" cellspacing="0">'
                     f'<tr>{tds}</tr></table>'
                     f'<div style="font:400 12px/1.6 {SANS};color:{P["dim"]};'
                     f'padding-top:9px">{sub}</div>'))

    # ---- accounts
    accts = sorted(set(m["recv_by"]) | set(m["sent_by"]),
                   key=lambda a: (-(m["recv_by"][a] + m["sent_by"][a] * 5), a))
    if accts:
        peak = max([m["recv_by"][a] for a in accts] + [1])
        rows = []
        for a in accts[:14]:
            r, sn = m["recv_by"][a], m["sent_by"][a]
            b = baseline.get(a)
            if b and b["n"] >= 3 and b["recv"] >= 1:
                d = pct(r - b["recv"], b["recv"])
                delta = f'{d:+.0f}%'
                dcol = P["bad"] if abs(d) >= 50 else P["dim"]
            else:
                delta, dcol = "&ndash;", P["dim"]
            w = max(2, int(r / peak * 100)) if r else 0
            bar = (f'<div style="height:8px;width:{w}%;background:{P["s1"]};'
                   f'border-radius:2px"></div>') if w else ""
            sent = (f'<span style="color:{P["s2"]};font-weight:700">{sn}</span>'
                    if sn else f'<span style="color:{P["dim"]}">0</span>')
            rows.append(
                f'<tr>'
                f'<td style="font:400 13px/1.9 {MONO};color:{P["ink"]};'
                f'padding-right:14px;white-space:nowrap">{e(a)}</td>'
                f'<td align="right" style="font:400 13px/1.9 {MONO};'
                f'color:{P["ink"]};padding-right:10px">{r}</td>'
                f'<td align="right" style="font:400 13px/1.9 {MONO};'
                f'padding-right:10px">{sent}</td>'
                f'<td align="right" style="font:400 12px/1.9 {MONO};color:{dcol};'
                f'padding-right:14px;white-space:nowrap">{delta}</td>'
                f'<td width="45%" style="padding-right:2px">{bar}</td></tr>')
        hdr = (f'<tr><td></td>'
               f'<td align="right" style="font:600 10px/1.6 {SANS};color:{P["dim"]};'
               f'letter-spacing:.06em;text-transform:uppercase">recv</td>'
               f'<td align="right" style="font:600 10px/1.6 {SANS};color:{P["dim"]};'
               f'letter-spacing:.06em;text-transform:uppercase">sent</td>'
               f'<td align="right" style="font:600 10px/1.6 {SANS};color:{P["dim"]};'
               f'letter-spacing:.06em;text-transform:uppercase">'
               f'vs {CFG["baseline_days"]}d</td><td></td></tr>')
        out.append(_card("Accounts", P["key"],
                         f'<table role="presentation" width="100%" cellpadding="0" '
                         f'cellspacing="0">{hdr}{"".join(rows)}</table>'))

    # ---- authentication
    total_fail = m["auth_fail"] + m["dovecot_fail"]
    if total_fail:
        ips = len(m["auth_ips"] | m["dovecot_ips"])
        col = P["bad"] if total_fail >= CFG["th_auth_fail"] else P["warn"]
        body = _mono(
            f'<b style="color:{col}">{total_fail} failures</b> '
            f'({m["auth_fail"]} smtp, {m["dovecot_fail"]} imap) from '
            f'<b>{ips}</b> addresses')
        tg = (m["auth_targets"] + m["dovecot_targets"]).most_common(4)
        if tg:
            body += _mono(
                "targets: " + " &nbsp;".join(f'{e(u)} <b>{n}</b>' for u, n in tg),
                P["dim"], "12px")
        if m["combo_users"]:
            ex = "".join(f'<div>{e(u)}</div>'
                         for u, _ in m["combo_users"].most_common(3))
            body += (
                f'<div style="margin-top:9px;padding:9px 11px;background:#fdf6e7;'
                f'border-radius:6px;font:400 12px/1.6 {SANS};color:{P["warn"]}">'
                f'<b>{sum(m["combo_users"].values())} attempts used breach-dump '
                f'usernames</b> &mdash; these addresses circulate in a public '
                f'combolist together with passwords used on those sites.'
                f'<div style="font:400 12px/1.7 {MONO};padding-top:6px">{ex}</div>'
                f'Check those mailbox passwords are not reused.</div>')
        out.append(_card("Authentication attack", col, body))

    # ---- front door: what knocked, versus what became mail
    if m["connects"]:
        att = len(m["auth_ips"] | m["dovecot_ips"])
        yielded = pct(m["received"], m["connects"])
        cells = [("connections", m["connects"]), ("unique IPs", len(m["conn_ips"])),
                 ("became mail", f'{yielded:.0f}%'), ("tried to auth", att)]
        tds = "".join(
            f'<td style="padding:0 16px 0 0;vertical-align:top">'
            f'<div style="font:700 18px/1.1 {SANS};color:{P["ink"]}">{v}</div>'
            f'<div style="font:400 11px/1.4 {SANS};color:{P["dim"]}">{k}</div></td>'
            for k, v in cells)
        body = (f'<table role="presentation" cellpadding="0" cellspacing="0">'
                f'<tr>{tds}</tr></table>')
        body += _mono(
            f'{m["probes"]} connected and vanished &middot; {m["tls_fail"]} failed '
            f'TLS &middot; {m["auth_drop"]} abandoned mid-authentication',
            P["dim"], "12px")
        worst = m.get("auth_ips_count", Counter()).most_common(3)
        if worst:
            body += _mono("worst offenders: " + " &nbsp;".join(
                f'{e(ip)} <b>{n}</b>' for ip, n in worst), P["dim"], "12px")
        out.append(_card("Front door", P["key"], body))

    # ---- which blocklists are earning their keep
    if m["dnsbl"]:
        wl = {z: n for z, n in m["dnsbl"].items()
              if "dnswl" in z or z.startswith("wl.")}
        bl = {z: n for z, n in m["dnsbl"].items() if z not in wl}
        body = ""
        if bl:
            top = sorted(bl.items(), key=lambda x: -x[1])[:7]
            mx = max(n for _, n in top)
            rows = "".join(
                f'<tr><td style="font:400 12px/1.9 {MONO};color:{P["ink"]};'
                f'padding-right:12px;white-space:nowrap">{e(short_zone(z))}</td>'
                f'<td align="right" style="font:400 12px/1.9 {MONO};'
                f'color:{P["ink"]};padding-right:10px">{n}</td>'
                f'<td width="60%"><div style="height:7px;width:'
                f'{max(2, int(n / mx * 100))}%;background:{P["s2"]};'
                f'border-radius:2px"></div></td></tr>' for z, n in top)
            body += _mono(
                f'<b>{len(m["dnsbl_ips"])} IPs</b> listed across '
                f'{len(bl)} blocklist(s)', P["ink"], "13px")
            body += (f'<table role="presentation" width="100%" cellpadding="0" '
                     f'cellspacing="0" style="margin-top:6px">{rows}</table>')
        if wl:
            body += _mono("allowlisted: " + ", ".join(
                f'{e(short_zone(z))} <b>{n}</b>'
                for z, n in sorted(wl.items(), key=lambda x: -x[1])),
                P["good"], "12px")
        out.append(_card("Blocklists", P["s2"], body))

    # ---- blocked
    if bans and (bans["live"] or bans["added"]):
        why = ", ".join(f'{e(r)} {n}' for r, n in bans["reasons"]) or "none today"
        body = _mono(
            f'<b style="color:{P["good"]}">{bans["added"]} banned today</b> '
            f'&middot; <b>{bans["live"]}</b> on the denylist now &middot; '
            f'{bans["expiring"]} expiring within 24h')
        body += _mono(f'added by: {why}', P["dim"], "12px")
        if m["bans"]:
            body += _mono(
                f'netfilter\'s own threshold rule banned {m["bans"]} separately',
                P["dim"], "12px")
        out.append(_card("Blocked", P["good"], body))

    # ---- rejects
    if m["reject_reasons"] and m["hard_reject"]:
        body = _mono("; ".join(f'{e(r)} <b>{n}</b>'
                               for r, n in m["reject_reasons"].most_common(4)))
        out.append(_card("Rejects", P["key"], body))

    # ---- new warning classes
    if new_classes:
        rows = "".join(
            f'<div><span style="color:{P["dim"]}">{n}&times;</span> '
            f'{e(m["warn_example"].get(cls, cls)[:110])}</div>'
            for cls, n in new_classes[:6])
        out.append(_card(
            f"New warning classes &mdash; {len(new_classes)} not seen in "
            f"{CFG['baseline_days']} days", P["warn"], _mono(rows, P["ink"], "12px")))

    # ---- llm triage
    if llm:
        seen = Counter(l.strip() for l in llm.splitlines() if l.strip())
        rows = []
        for line, n in seen.most_common(12):
            verd = line.split()[0].lower() if line.split() else ""
            col = {"act": P["bad"], "note": P["warn"]}.get(verd, P["dim"])
            rest = line[len(verd):].strip()
            rows.append(
                f'<div><b style="color:{col};text-transform:uppercase">{e(verd)}</b> '
                f'<span style="color:{P["ink"]}">{e(rest[:100])}</span>'
                + (f' <span style="color:{P["dim"]}">&times;{n}</span>' if n > 1 else "")
                + '</div>')
        out.append(_card(
            f'Triage &mdash; {e(CFG["llm_model"])}, advisory only', P["dim"],
            _mono("".join(rows), P["ink"], "12px")))

    # ---- all clear
    ok = []
    if not m["auth_ok_unexpected"]:
        ok.append("no unexplained logins")
    if not m["bounced"] and not m["deferred"]:
        ok.append("no delivery failures")
    if not st["unhealthy"] and st["containers"] >= CFG["expected_containers"]:
        ok.append(f'{st["containers"]}/{CFG["expected_containers"]} containers up')
    if ok:
        body = _mono(" &middot; ".join(e(x) for x in ok), P["good"])
        for u, h, ip in sorted(set(m["auth_ok_external_known"])):
            body += _mono(f'expected external sender: {e(u)} via {e(h)}[{e(ip)}]',
                          P["dim"], "12px")
        out.append(_card("All clear", P["good"], body))

    # ---- caveats last: they qualify everything above
    notes = []
    if hist_days < CFG["baseline_days"]:
        notes.append(
            f'<b>Baseline building &mdash; {hist_days}/{CFG["baseline_days"]} days.</b> '
            f'Per-account deltas and new-warning detection start once there is a '
            f'full week of history.')
    short = {k: v for k, v in coverage.items() if not v["full"]}
    for key, v in sorted(short.items()):
        notes.append(
            f'<b>Coverage &mdash; {e(key)} did not reach back to the start of the '
            f'day</b>, missing the first {v["missing_hours"]:.1f}h '
            f'({v["entries"]} entries held). The counts above are LOW, not '
            f'reassuring: mailcow\'s log rings are fixed-size, and a chatty '
            f'service rolls its ring sooner than a quiet one.')
    if notes:
        out.append(_card("Read with care", P["warn"],
                         "".join(f'<div style="font:400 12px/1.65 {SANS};'
                                 f'color:{P["ink"]};padding-bottom:5px">{x}</div>'
                                 for x in notes)))

    out.append(
        f'<div style="font:400 11px/1.6 {SANS};color:{P["dim"]};padding-top:4px">'
        f'{m["lines"]} log lines from the Redis rings &middot; {e(date_s)} '
        f'&middot; per-mailbox chart attached</div>')

    return (f'<div style="margin:0;padding:22px 12px;background:{P["plane"]}">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
            f'<tr><td align="center"><table role="presentation" width="100%" '
            f'cellpadding="0" cellspacing="0" style="max-width:640px">'
            f'<tr><td>{"".join(out)}</td></tr></table></td></tr></table></div>')


# ---------------------------------------------------------------- delivery

def send(mcw, subject, body, html_doc, date_s, to_stdout=False, html_body=None):
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = CFG["mail_from"]
    msg["To"] = CFG["mail_to"]
    msg["Subject"] = subject
    msg.set_content(body)
    if html_body:
        # multipart/alternative: the plain text stays the canonical version and
        # is what a terminal, a pager or a text-only client shows. The HTML is a
        # presentation of the same numbers, never a superset of them.
        msg.add_alternative(html_body, subtype="html")
    if html_doc:
        msg.add_attachment(html_doc.encode(), maintype="text",
                           subtype="html",
                           filename=f"mail-{date_s}.html")
    if to_stdout:
        print(f"Subject: {subject}\n")
        print(body)
        return 0
    import subprocess
    p = subprocess.run(["docker", "exec", "-i",
                        mcw.container("postfix-mailcow"), "sendmail", "-t"],
                       input=msg.as_bytes(), capture_output=True)
    if p.returncode:
        sys.stderr.write(p.stderr.decode()[:500] + "\n")
    return p.returncode


def build_cfg(cp, mcw, db):
    """Flatten config into the CFG dict the rest of the module reads."""
    prompt = ""
    pf = mc.cfg_path(cp, "llm", "system_prompt_file")
    if pf and os.path.isfile(pf):
        with open(pf) as fh:
            prompt = "\n".join(l for l in fh.read().splitlines()
                               if not l.startswith(";")).strip()
    return {
        "mail_to": cp.get("digest", "mail_to"),
        "mail_from": cp.get("digest", "mail_from"),
        "hostname": cp.get("digest", "hostname"),
        "th_auth_fail": cp.getint("digest", "th_auth_fail", fallback=50),
        "th_deferred": cp.getint("digest", "th_deferred", fallback=5),
        "th_queue": cp.getint("digest", "th_queue", fallback=20),
        "th_sent_spike": cp.getint("digest", "th_sent_spike", fallback=25),
        "th_cert_days": cp.getint("digest", "th_cert_days", fallback=21),
        "baseline_days": cp.getint("digest", "baseline_days", fallback=7),
        "chart_days": cp.getint("digest", "chart_days", fallback=30),
        "ignore_users": set(mc.cfg_list(cp, "digest", "ignore_users",
                                        "watchdog@invalid")),
        "trusted_auth": mc.cfg_networks(cp, "digest", "trusted_auth",
                                        "127.0.0.0/8"),
        "auth_allow": [(k.lower(), v.lower())
                       for k, v in (cp.items("auth_allow")
                                    if cp.has_section("auth_allow") else [])],
        "expected_containers": mcw.expected_containers(cp, db),
        "llm_enabled": cp.getboolean("llm", "enabled", fallback=False),
        "llm_url": cp.get("llm", "url", fallback=""),
        "llm_model": cp.get("llm", "model", fallback=""),
        "llm_timeout": cp.getint("llm", "timeout", fallback=90),
        "llm_prompt": prompt,
    }


def main():
    global CFG
    ap = argparse.ArgumentParser(description="daily mailcow digest")
    ap.add_argument("--config")
    ap.add_argument("--date", help="YYYY-MM-DD (default: yesterday)")
    ap.add_argument("--stdout", action="store_true", help="print instead of mailing")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--html-out", help="also write the chart page to this path")
    ap.add_argument("--email-out",
                    help="also write the HTML mail body to this path")
    ap.add_argument("--check-config", action="store_true",
                    help="validate configuration and connectivity, then exit")
    ap.add_argument("--version", action="version", version=mc.__version__)
    a = ap.parse_args()

    try:
        cp = mc.load_config(a.config)
    except mc.ConfigError as e:
        mc.die(str(e))

    mcw = mc.Mailcow(cp)
    state = cp.get("state", "dir", fallback="/var/lib/mailcow-sentinel")
    c = mc.db_open(f"{state}/history.db")
    CFG = build_cfg(cp, mcw, c)

    if a.check_config:
        print(f"config      {cp.config_path}")
        print(f"mailcow     {mcw.dir}  project={mcw._project}")
        print(f"redis       {mcw.container('redis-mailcow')}")
        print(f"postfix     {mcw.container('postfix-mailcow')}")
        print(f"state       {state}/history.db")
        print(f"mail_to     {CFG['mail_to']}")
        print(f"hostname    {CFG['hostname']}")
        print(f"containers  expect {CFG['expected_containers']}, "
              f"running {mcw.container_count()}")
        print(f"cert        {mcw.cert_path}")
        print(f"llm         {'on: ' + CFG['llm_url'] if CFG['llm_enabled'] else 'off'}")
        ok = bool(mcw.conf("REDISPASS")) and CFG["expected_containers"] > 0
        print("\n" + ("OK" if ok else "PROBLEM: check REDISPASS and docker access"))
        return 0 if ok else 2

    day = (dt.date.fromisoformat(a.date) if a.date
           else dt.date.today() - dt.timedelta(days=1))
    date_s = day.isoformat()
    start = dt.datetime.combine(day, dt.time.min).timestamp()
    end = start + 86400

    m = collect(mcw, start, end)
    st = system_state(mcw)
    coverage = mcw.coverage(start)

    bans = db_bans(c, start, end)
    hist_days = db_history_days(c, date_s)
    baseline = db_baseline(c, date_s, CFG["baseline_days"])
    new_classes = db_new_classes(c, date_s, m, CFG["baseline_days"])
    db_save(c, date_s, m)

    llm = None
    if CFG["llm_enabled"] and not a.no_llm:
        llm = llm_triage(new_classes, m["warn_example"])
    level, reasons = verdict(m, st, baseline, new_classes,
                             CFG["expected_containers"])

    head = reasons[0] if reasons else "nothing unusual"
    if len(head) > 58:
        head = head[:55].rstrip(" ,;(") + "..."
    subject = (f"[{CFG['hostname']}] {level} - {head} - "
               f"{m['received']} in / {m['external']} out")
    body = (f"VERDICT     {level} - "
            f"{'; '.join(reasons) if reasons else 'nothing unusual'}\n\n"
            + render_text(date_s, m, st, baseline, new_classes, llm,
                          coverage, hist_days, bans))
    html_doc = render_html(date_s, m, db_series(c, date_s, CFG["chart_days"]),
                           level)
    html_body = render_email_html(date_s, m, st, baseline, new_classes, llm,
                                  coverage, hist_days, bans, level, reasons)
    c.close()
    if a.html_out:
        with open(a.html_out, "w") as fh:
            fh.write(html_doc)
    if a.email_out:
        with open(a.email_out, "w") as fh:
            fh.write(html_body)
    return send(mcw, subject, body, html_doc, date_s, a.stdout, html_body)


if __name__ == "__main__":
    sys.exit(main())
