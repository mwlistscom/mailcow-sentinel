#!/usr/bin/env python3
"""
authguard -- ban credential-stuffing sources that a per-IP threshold cannot see,
using two signals a legitimate client is incapable of producing.

Why this exists
---------------
mailcow's netfilter bans an IP after `max_attempts` failures inside
`retry_window` (stock: 3 in 600 s).  Against a modern distributed attack that is
close to inert.  Measured on one small server over 41 hours: **669 failed AUTH
attempts from 326 distinct IPs, of which half tried exactly once**, and 88 more
tried twice.  The native rule fired 7 times and stopped 4 attempts -- **0.6%**.

That is not a misconfiguration.  It is the ceiling of counting per IP: an
address that knocks once can never trip a threshold, whatever you set it to.

Raising the threshold does not rescue it, and is actively dangerous.  A phone
left on a stale password looks *identical* to a botnet node assigned a single
target.  Simulated against the same 41 hours:

    policy               bans  attempts stopped  bans a stale client?
    3 in 600 s (stock)      7          4 (0.6%)  no
    3 in 1 h               12         18 (2.7%)  unlikely
    3 in 24 h              86        103  (15%)  YES, after 3 retries
    2 in 24 h             223        178  (27%)  YES, after 2
    netban /24             91        113  (17%)  YES, plus neighbours
    authguard             111        145  (22%)  no -- by construction

`/24` netban was tested and rejected: 91 bans versus 86 means the botnet does
not cluster in subnets, so it is all collateral risk for no yield.

So this bans on shape, not volume.  Two signals:

  1. ONE SOURCE, MANY MAILBOXES.  An IP attempting >= 2 distinct identities is
     enumerating.  A real client only ever knows its own address, even when
     badly misconfigured.  Measured: 79 IPs, 310 attempts.

  2. AN IDENTITY THAT CANNOT EXIST.  Anything absent from mailbox+alias --
     including combolist artefacts, where a site URL is still welded to the
     address, e.g. `httpswww.example.comuser@example.com`.  No client of yours
     can emit that string.  Measured: 55 IPs, 154 attempts.

Together they matched 111 of 326 IPs (34%) covering 351 of 669 attempts (52%),
and cannot fire on an address that only ever tried its own single real mailbox.

Deliberately NOT covered: the 247 IPs that tried exactly one *real* mailbox.
They are indistinguishable from a misconfigured client, so they are left to the
native threshold.  That is a real gap and an accepted one -- this tool reduces
noise; rotating exposed passwords is what actually ends the risk.

Mechanism
---------
Writes to mailcow's own denylist (Redis hash `F2B_BLACKLIST`, value `1`, exactly
as the UI writes it); netfilter applies it within 60 s.  Because that ban is
*permanent* and residential addresses get reassigned, entries this tool added
expire after `ban_ttl_days`.  Only entries it added are ever removed -- a
HEXISTS check stops it taking ownership of yours.

Note: saving the denylist in the mailcow UI rewrites the whole key, so entries
added here disappear until the next run re-adds them (<= one interval).  Harmless.

Usage:  authguard.py [--dry-run] [--report] [--check-config] [--config PATH]
"""

import argparse
import datetime as dt
import re
import sys
import time
from collections import defaultdict

import mcsentinel_common as mc

RE_BRACKET_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
RE_USERNAME = re.compile(r"sasl_username=(\S+)")
RE_SASL_OK = re.compile(r"sasl_method=\S+, sasl_username=(\S+)")
RE_OK_IP = re.compile(r"client=[^\[]*\[(\d{1,3}(?:\.\d{1,3}){3})\]")
RE_DOVECOT_CTX = re.compile(r"\w+\(([^,]+),(\d{1,3}(?:\.\d{1,3}){3})")


def canon(u, full, domains):
    """Normalise an attempted identity so `alice` and `alice@d` are one thing.

    Without this, a bot alternating between the bare and qualified form of the
    SAME mailbox would look like two distinct identities and trip signal 1 on
    its own -- which would make a stale client bannable after all.
    """
    u = u.strip().lower()
    if "@" in u:
        return u
    for d in sorted(domains):
        if f"{u}@{d}" in full:
            return f"{u}@{d}"
    return u


def collect(mcw, since, ignore_suffix="@invalid"):
    """-> (fails {ip: {raw identity}}, ok_ips {ip})"""
    fails, ok = defaultdict(set), set()

    for ts, _prog, msg in mcw.ring("POSTFIX_MAILLOG"):
        if ts < since:
            continue
        if "SASL" in msg and "authentication failed" in msg:
            ip, u = RE_BRACKET_IP.search(msg), RE_USERNAME.search(msg)
            if ip and u:
                fails[ip.group(1)].add(u.group(1).strip().lower())
        m = RE_SASL_OK.search(msg)
        if m:
            ipm = RE_OK_IP.search(msg)
            if ipm:
                ok.add(ipm.group(1))

    for ts, _prog, msg in mcw.ring("DOVECOT_MAILLOG"):
        if ts < since:
            continue
        if "Password mismatch" in msg or "unknown user" in msg:
            ctx = RE_DOVECOT_CTX.search(msg)
            if ctx and not ctx.group(1).endswith(ignore_suffix):
                fails[ctx.group(2)].add(ctx.group(1).strip().lower())

    return fails, ok


def main():
    ap = argparse.ArgumentParser(description="ban credential-stuffing sources by shape")
    ap.add_argument("--config")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be banned, change nothing")
    ap.add_argument("--report", action="store_true",
                    help="print the live list this tool maintains, then exit")
    ap.add_argument("--check-config", action="store_true",
                    help="validate configuration and connectivity, then exit")
    ap.add_argument("--lookback-hours", type=int)
    ap.add_argument("--version", action="version", version=mc.__version__)
    a = ap.parse_args()

    try:
        cp = mc.load_config(a.config)
    except mc.ConfigError as e:
        mc.die(str(e))

    mcw = mc.Mailcow(cp)
    state = cp.get("state", "dir", fallback="/var/lib/mailcow-sentinel")
    db = mc.db_open(f"{state}/history.db")

    lookback = a.lookback_hours or cp.getint("authguard", "lookback_hours", fallback=24)
    ttl_days = cp.getint("authguard", "ban_ttl_days", fallback=7)
    max_list = cp.getint("authguard", "max_list", fallback=5000)
    keep_ok = cp.getint("authguard", "seen_ok_retention_days", fallback=30)
    never = mc.cfg_networks(cp, "authguard", "never_ban",
                            "127.0.0.0/8\n10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16")
    now = int(time.time())

    if a.check_config:
        full, locals_, domains = mcw.valid_identities()
        print(f"config      {cp.config_path}")
        print(f"mailcow     {mcw.dir}  project={mcw._project}")
        print(f"redis       {mcw.container('redis-mailcow')}")
        print(f"mysql       {mcw.container('mysql-mailcow')}")
        print(f"state       {state}/history.db")
        print(f"identities  {len(full)} addresses across {len(domains)} domain(s)")
        print(f"never_ban   {', '.join(str(n) for n in never)}")
        print(f"ttl         {ttl_days} days   lookback {lookback}h   cap {max_list}")
        ok = bool(full) and bool(mcw.conf("REDISPASS"))
        print("\n" + ("OK" if ok else "PROBLEM: could not read identities or REDISPASS"))
        return 0 if ok else 2

    if a.report:
        rows = db.execute("SELECT ip, added_ts, expires_ts, reason, detail "
                          "FROM authguard_ban ORDER BY added_ts DESC").fetchall()
        print(f"{len(rows)} entries maintained by authguard\n")
        for ip, added, exp, reason, detail in rows[:60]:
            print(f"  {ip:<16} {dt.datetime.fromtimestamp(added):%Y-%m-%d %H:%M}"
                  f"  -> {dt.datetime.fromtimestamp(exp):%m-%d}  {reason}"
                  f"  {detail[:60]}")
        return 0

    # A truncated or failed mailbox query would make every identity look
    # non-existent and ban the world.  Refuse unless the count is plausible,
    # judged against the last count we trusted.
    full, locals_, domains = mcw.valid_identities()
    prev = int(mc.meta_get(db, "identity_count", 0) or 0)
    if len(full) < max(5, prev // 2):
        mc.die(f"refusing to run: mailbox list returned {len(full)} identities, "
               f"previously {prev}. Not banning on a bad query.", 3)

    fails, ok_ips = collect(mcw, now - lookback * 3600)

    # ---- read phase: decide, touching no external state
    ever_ok = {r[0] for r in db.execute(
        "SELECT ip FROM authguard_seen_ok WHERE last_ts > ?",
        (now - keep_ok * 86400,))}
    already = {r[0] for r in db.execute("SELECT ip FROM authguard_ban")}
    whitelisted = set(mcw.redis("HKEYS", "F2B_WHITELIST").split())

    candidates = []
    for ip, raw in fails.items():
        if ip in already or ip in ever_ok or ip in whitelisted:
            continue
        if mc.in_networks(ip, never):
            continue
        idents = {canon(u, full, domains) for u in raw}
        impossible = sorted(i for i in idents
                            if i not in full and i.split("@")[0] not in locals_)
        if len(idents) >= 2:
            reason = "enumerating"
            detail = f"{len(idents)} identities: " + ", ".join(sorted(idents)[:4])
        elif impossible:
            reason, detail = "nonexistent-identity", impossible[0]
        else:
            continue
        candidates.append((ip, reason, detail))

    expired = [r[0] for r in db.execute(
        "SELECT ip FROM authguard_ban WHERE expires_ts <= ?", (now,))]

    if a.dry_run:
        print(f"lookback {lookback}h  |  {len(fails)} source IPs seen  |  "
              f"{len(already)} already listed")
        print(f"\nwould ADD {len(candidates)}:")
        for ip, reason, detail in sorted(candidates)[:40]:
            print(f"  + {ip:<16} {reason:<22} {detail[:70]}")
        print(f"\nwould EXPIRE {len(expired)}: {expired[:12]}")
        return 0

    # ---- write phase.  Ledger row FIRST, then Redis.
    # If this dies between the two, the outcome is a recorded ban that was never
    # applied -- which the next run simply reapplies.  The other order leaves a
    # ban in Redis with no expiry record, indistinguishable from an operator's
    # own entry, which this tool then deliberately refuses to touch: permanent
    # by accident, and unrecoverable without hand-editing.
    added, removed = 0, 0
    for ip, reason, detail in candidates:
        if len(already) + added >= max_list:
            sys.stderr.write(f"list cap {max_list} reached; stopping\n")
            break
        if mcw.redis("HEXISTS", "F2B_BLACKLIST", ip).strip() == "1":
            continue                      # operator's entry -- leave it alone
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT OR REPLACE INTO authguard_ban VALUES (?,?,?,?,?)",
                   (ip, now, now + ttl_days * 86400, reason, detail))
        db.execute("COMMIT")
        if mcw.redis("HSET", "F2B_BLACKLIST", ip, "1") == "":
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM authguard_ban WHERE ip=?", (ip,))
            db.execute("COMMIT")
            continue
        added += 1

    for ip in expired:
        mcw.redis("HDEL", "F2B_BLACKLIST", ip)
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM authguard_ban WHERE ip=?", (ip,))
        db.execute("COMMIT")
        removed += 1

    db.execute("BEGIN IMMEDIATE")
    for ip in ok_ips:
        db.execute("INSERT OR REPLACE INTO authguard_seen_ok VALUES (?,?)", (ip, now))
    db.execute("DELETE FROM authguard_seen_ok WHERE last_ts < ?",
               (now - keep_ok * 86400,))
    mc.meta_set(db, "identity_count", len(full))
    mc.meta_set(db, "authguard_last_run", now)
    db.execute("COMMIT")

    live = db.execute("SELECT COUNT(*) FROM authguard_ban").fetchone()[0]
    db.close()
    if added or removed:
        print(f"{dt.datetime.now():%Y-%m-%d %H:%M} +{added} -{removed} (live {live})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
