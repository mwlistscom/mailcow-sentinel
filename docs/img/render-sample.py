#!/usr/bin/env python3
"""Regenerate examples/sample-digest.txt from synthetic data.

    python3 docs/img/render-sample.py

Calls maildigest.render_text() directly, so the sample cannot drift from the
renderer's actual formatting -- column widths, truncation and all.

Do NOT produce the sample by substituting names into real output. It was tried:
the account table is fixed-width, so swapping an 18-character address for a
16-character one shears every column, and the combolist artefacts glue the local
part onto a domain ("...amazon.comalice@example.com") where a word-boundary
regex never fires. Generate it; do not launder it.
"""

import datetime as dt
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

import maildigest as md  # noqa: E402

DATE = "2026-09-09"
OUT = os.path.join(ROOT, "examples", "sample-digest.txt")

md.CFG = {
    "hostname": "mail.example.com", "mail_to": "admin@example.com",
    "mail_from": "sentinel@example.com", "th_auth_fail": 50, "th_deferred": 5,
    "th_queue": 20, "th_sent_spike": 25, "th_cert_days": 21,
    "baseline_days": 7, "chart_days": 30, "expected_containers": 18,
    "llm_model": "qwen3.6:27b", "trusted_auth": [], "auth_allow": [],
    "ignore_users": set(), "llm_enabled": True, "llm_url": "", "llm_timeout": 90,
    "llm_prompt": "",
}

m = {
    "received": 168, "delivered": 157, "local": 157, "external": 1,
    "deferred": 0, "bounced": 0, "rejected": 24, "greylisted": 14,
    "hard_reject": 10, "lines": 6058, "bans": 5,
    "recv_by": Counter({"alice@example.com": 58, "dave@example.com": 35,
                        "carol@example.com": 28, "erin@example.com": 27,
                        "bob@example.com": 14, "postmaster@example.com": 2,
                        "help@example.net": 1}),
    "sent_by": Counter({"app@example.com": 1}),
    "auth_fail": 223, "dovecot_fail": 102,
    "auth_ips": {f"203.0.113.{i}" for i in range(10, 120)},
    "dovecot_ips": {f"198.51.100.{i}" for i in range(10, 66)},
    "auth_ips_count": Counter({"203.0.113.24": 12, "203.0.113.85": 7,
                               "198.51.100.14": 7}),
    "auth_targets": Counter({"bob@example.com": 131, "carol@example.com": 74,
                             "alice@example.com": 68, "bob": 13}),
    "dovecot_targets": Counter(),
    "combo_users": Counter({"httpswww.amazon.comalice@example.com": 4,
                            "httpspa.fadv.combob@example.com": 3,
                            "www.att.commyalice@example.com": 1}),
    "auth_ok": [], "auth_ok_unexpected": [],
    "auth_ok_external_known": [("app@example.com", "webhost.example.net",
                                "203.0.113.7")],
    "reject_reasons": Counter({"Greylisted, please try again later": 11,
                               "Service unavailable": 8, "Protocol error": 2}),
    "connects": 678, "conn_ips": {f"10.{i}.0.1" for i in range(471)},
    "probes": 254, "tls_fail": 247, "auth_drop": 212, "allowlisted": 130,
    "dnsbl": Counter({"hostkarma.junkemailfilter.com": 112,
                      "zen.dq.spamhaus.net": 74, "bl.mailspike.net": 3,
                      "bl.spameatingmonkey.net": 3, "bl.spamcop.net": 2,
                      "bl.suomispam.net": 1, "list.dnswl.org": 20,
                      "wl.mailspike.net": 6}),
    "dnsbl_ips": {f"203.0.113.{i}" for i in range(10, 79)},
    "warn_classes": Counter(),
    "warn_example": {
        "a": "warning: TLS SNI from unknown[203.0.113.9] is invalid: 198.51.100.1",
        "b": "warning: hostname scanner.example.net does not resolve to address "
             "203.0.113.44",
    },
}
st = {"containers": 18, "unhealthy": [], "queue": 0, "cert_days": 57}
baseline = {}
new_classes = [("a", 9), ("b", 2)]
llm = ("ignore Automated scanner probing non-SMTP ports and invalid SNI.\n"
       "note Transient DNS failure for an external sender hostname.\n"
       "note Transient DNS failure for an external sender hostname.")
coverage = {"POSTFIX_MAILLOG": {"entries": 10003, "oldest": 0, "full": True,
                                "missing_hours": 0.0}}
bans = {"live": 96, "added": 31, "expiring": 4,
        "reasons": [("enumerating", 22), ("nonexistent-identity", 9)],
        "oldest": 0}
repeat = {
    "rows": [("203.0.113.24", 6, 41, "2026-09-04", 0),
             ("203.0.113.85", 4, 12, "2026-09-06", 0),
             ("198.51.100.14", 3, 9, "2026-09-07", 1)],
    "total": 11, "never_banned": 8, "returning": 23, "today": 166,
    "window": 7, "days_held": 7, "min_days": 2,
}

text = md.render_text(DATE, m, st, baseline, new_classes, llm, coverage,
                      hist_days=7, bans=bans, repeat=repeat)
head = ("VERDICT" + " " * (md.LBL - 7)
        + "ATTENTION - credential stuffing vs bob@, carol@, alice@;\n"
        + " " * md.LBL + "breach-dump usernames in use against this server\n\n")
with open(OUT, "w") as fh:
    fh.write(head + text + "\n")
print(f"  {OUT}: {len(text.splitlines()) + 3} lines")
