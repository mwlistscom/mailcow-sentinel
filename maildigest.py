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
        "combo_users": Counter(),
        "auth_ok": [], "auth_ok_unexpected": [], "auth_ok_external_known": [],
        "dovecot_fail": 0, "dovecot_ips": set(), "dovecot_targets": Counter(),
        "warn_classes": Counter(), "warn_example": {},
        "bans": 0, "ban_ips": set(),
        "reject_reasons": Counter(),
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
            rm = re.search(r"\b[45]\.\d\.\d\s+([^;]{0,60})", msg)
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


def render_text(date_s, m, st, baseline, new_classes, llm, coverage, hist_days):
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
        for line in llm.splitlines()[:12]:
            if line.strip():
                add(f"              {line.strip()[:92]}")
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


# ---------------------------------------------------------------- delivery

def send(mcw, subject, body, html_doc, date_s, to_stdout=False):
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = CFG["mail_from"]
    msg["To"] = CFG["mail_to"]
    msg["Subject"] = subject
    msg.set_content(body)
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
                          coverage, hist_days))
    html_doc = render_html(date_s, m, db_series(c, date_s, CFG["chart_days"]),
                           level)
    c.close()
    if a.html_out:
        with open(a.html_out, "w") as fh:
            fh.write(html_doc)
    return send(mcw, subject, body, html_doc, date_s, a.stdout)


if __name__ == "__main__":
    sys.exit(main())
