# mailcow-sentinel

**mailcow's per-IP ban rule stopped 0.6% of a real credential-stuffing attack.
Here is the measurement, why the obvious fix is worse, and what to do instead.**

Two stdlib-only Python tools for [mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized):

- **`authguard`** — bans credential-stuffing sources by *shape* rather than by volume.
- **`maildigest`** — replaces a 799-line daily report with 33 lines and a verdict in the Subject.

No dependencies. No pip, no venv, no packaging. Clone and run.

---

## The problem, measured

One small mail server, 41 hours of real traffic:

| | |
|---|---:|
| Failed `AUTH` attempts | **669** |
| Distinct source IPs | **326** |
| IPs that tried **exactly once** | **162 (50%)** |
| IPs that tried twice | 88 |
| Bans issued by the stock rule (3 in 600 s) | **7** |
| Attempts that rule actually stopped | **4 — 0.6%** |

The stock rule is not misconfigured. It is at the ceiling of what per-IP counting
can do: **an address that knocks once can never trip a threshold**, whatever you
set it to. Half this botnet knocked once.

## Why the obvious fix is worse

Every alternative, simulated against the same 41 hours. The rightmost column is
the one that decides it:

| policy | bans | attempts stopped | bans a client with a stale password? |
|---|---:|---:|---|
| 3 in 600 s *(stock)* | 7 | 4 (0.6%) | no |
| 3 in 1 h | 12 | 18 (2.7%) | unlikely |
| 3 in 24 h | 86 | 103 (15%) | **yes, after 3 retries** |
| 2 in 24 h | 223 | 178 (27%) | **yes, after 2** |
| netban `/24` | 91 | 113 (17%) | **yes, plus neighbours** |
| **authguard** | **111** | **145 (22%)** | **no — by construction** |

Widening the window is the tempting fix and it is a trap. A phone left on a stale
password looks *identical* to a botnet node assigned a single target — both make a
handful of failed attempts against one real mailbox. Rotate your users' passwords
and 24-hour thresholds start banning your own users' handsets.

`/24` netban was tested and **rejected**: 91 bans versus 86 means this botnet does
not cluster in subnets, so aggregating to networks is all collateral risk and no
yield.

## Ban on shape, not volume

Two signals, each of which a legitimate client is structurally incapable of
producing:

**1. One source, many mailboxes.** An IP attempting ≥ 2 distinct identities is
enumerating. A real client only ever knows its own address, even when badly
misconfigured. *Measured: 79 IPs, 310 attempts.*

```
203.0.113.47 -> alice@example.com, bob@example.com,
                   carol@example.com, httpswww.att.combob@example.com
```

**2. An identity that cannot exist.** Anything absent from mailcow's `mailbox` +
`alias` tables — which catches combolist artefacts, where a site URL is still
welded to the address because whatever parsed the breach dump ate the delimiter.
No client of yours can emit that string. *Measured: 55 IPs, 154 attempts.*

```
httpswww.amazon.comalice@example.com
httpssignin.ea.combob@example.com
httpswww.plex.tvalice@example.com
```

Together: **111 of 326 IPs, covering 351 of 669 attempts.** Neither can fire on an
address that only ever tried its own single, real mailbox.

## The honest gap

**247 IPs tried exactly one real mailbox and are deliberately left alone.** They
are genuinely indistinguishable from a misconfigured client, so they stay with the
native threshold. This is a heuristic with a stated blind spot, not a solution to
credential stuffing.

Be clear about what actually ended the risk on the server this was built for:
**rotating the exposed passwords did.** authguard reduced the noise. If your
addresses are in a combolist — and the `httpswww.…` usernames are proof that
someone's are — rotate first, then install this.

---

## The digest

None of the above would have been noticed without fixing the reporting first.

The daily `pflogsumm` mail ran to **799 lines / 50 KB**. Its largest section was
288 lines of Warnings — **192 of which were one credential-stuffing campaign**,
rendered as near-identical truncated lines, one per attacking IP. The most
important thing in the report was present, and it read as wallpaper. Another ~440
lines were per-sender and per-domain enumerations nobody reads on a phone.

What arrives instead — the whole thing, 37 lines:

![A mailcow-sentinel daily digest: a verdict of ATTENTION for credential stuffing
in the Subject, then mail flow totals, per-mailbox send and receive volumes, an
authentication attack summary naming the targeted mailboxes and the breach-dump
usernames used against them, new warning classes, and a closing health
line.](docs/img/digest.svg)

*(Plain-text version: [`examples/sample-digest.txt`](examples/sample-digest.txt).
Synthetic data throughout — see [Caveats](#caveats).)*

An HTML chart of per-mailbox volume is attached. Outbound is the compromise
tripwire: on most small servers the baseline is *zero*, so any sustained outbound
from a mailbox is visible immediately with no threshold tuning.

### Four things it does that a log summariser does not

**Reads the Redis rings, not `docker compose logs`.** Container logs reset when
the container is recreated — which is the documented procedure for changing
postfix config. A log-based report silently covers a few hours the morning after
you touch anything, and looks reassuringly quiet.

**Reports ring coverage per ring.** The rings are fixed-size and a chatty service
rolls its ring sooner than a quiet one. On the reference server `POSTFIX_MAILLOG`
spans ~41 h but `DOVECOT_MAILLOG` only ~18 h, so a full previous day of IMAP
simply is not there. It says so rather than printing a confident undercount:

```
! COVERAGE  a log ring did not reach back to the start of the day;
            the counts above are LOW, not reassuring:
              DOVECOT_MAILLOG    missing the first 20.5h  (10000 entries held)
```

**A whole calendar day, not a rolling 24 h.** A rolling window straddles two
dates, which makes day-over-day comparison impossible — and that comparison is
what makes a spike visible.

**No credentials.** It mails via `docker exec postfix sendmail -t`. There is no
SMTP password to leak because there is no SMTP password.

### The optional local LLM

Points at any Ollama-compatible endpoint. It classifies **only** warning classes
that are new versus the baseline, it **never produces a number** — every figure is
a deterministic count — and it never blocks: on timeout the digest sends without
the `TRIAGE` block.

Give it your local ground rules in `llm_prompt.txt`. Asked to triage cold, a model
here confidently advised *"fix main.cf settings immediately"* — which mailcow
regenerates on every start, so the advice was actively wrong. It has no way to
know unless you tell it. Constrain it to classify, never to prescribe.

---

## Install

Requires Python 3.8+, docker, and a mailcow-dockerized deployment. Runs as root:
it reads `mailcow.conf` (mode 0600) and talks to the docker socket. Being in the
`docker` group is root-equivalent, so there is no meaningful unprivileged mode.

```bash
git clone https://github.com/mwlistscom/mailcow-sentinel
cd mailcow-sentinel
sudo ./install.sh
sudo $EDITOR /etc/mailcow-sentinel/config.ini      # 3 required settings
sudo /opt/mailcow-sentinel/maildigest.py --check-config
sudo /opt/mailcow-sentinel/authguard.py --check-config
```

Then try it without changing anything:

```bash
sudo /opt/mailcow-sentinel/authguard.py --dry-run              # what it would ban
sudo /opt/mailcow-sentinel/maildigest.py --date 2026-09-09 --stdout --no-llm
```

`install.sh` prints the two cron lines; it does not install them for you.

### Ban lifetime

mailcow's denylist has **no expiry** — anything in `F2B_BLACKLIST` is banned
forever. Since most of these are residential addresses that DHCP reassigns,
authguard ages out its own entries after `ban_ttl_days` (default 7) and netfilter
releases them on its next poll. It only ever removes entries it added; a `HEXISTS`
check stops it taking ownership of yours.

To release one early, do **both** — dropping only the Redis key means it returns
on the next run:

```bash
redis-cli -a "$REDISPASS" HDEL F2B_BLACKLIST <ip>
sqlite3 /var/lib/mailcow-sentinel/history.db \
  "DELETE FROM authguard_ban WHERE ip='<ip>'"
```

### Configuration

Everything site-specific is in `/etc/mailcow-sentinel/config.ini`; see
[`config.example.ini`](config.example.ini), which documents every key. Three
settings are required and have no default — a tool that emails reports must never
guess who to mail.

The tool deliberately does **not** ask you to declare your mail domains: it reads
them from mailcow. A forgotten config key there would make every bare-username
attempt look like a nonexistent identity, i.e. it would ban *more* when
misconfigured, which is the wrong direction for a banning tool to fail in.

Thresholds default to values measured on a small server (~150 messages/day
inbound). On a busier host raise `th_auth_fail` and `th_sent_spike`, or every day
reads as ATTENTION and you stop reading the mail. See [`docs/TUNING.md`](docs/TUNING.md).

---

## Prior art

fail2ban cannot express this either. There is no standard jail for "one source,
many usernames" ([discussion](https://github.com/fail2ban/fail2ban/discussions/3166)),
and distributed attacks stay under per-IP thresholds
[by design](https://github.com/fail2ban/fail2ban/issues/1784). mailcow ships no
fail2ban container at all — it uses `netfilter-mailcow` with Redis regex rules,
which share a single per-IP counter across every rule, so a "ban immediately on
this pattern" rule cannot be expressed natively. That gap is why this exists.

## Caveats

- Tested against one mailcow deployment. The measurements are from **one small
  server over 41 hours** — treat them as an illustration of the failure mode, not
  as universal constants.
- It writes to mailcow's own denylist. If you edit the denylist in the mailcow UI,
  the save rewrites the whole key and authguard's entries vanish until the next
  run re-adds them (≤ one interval). Harmless, but do not be alarmed.
- `history.db` accumulates banned addresses, the identities they attempted, and
  your per-mailbox mail volumes. It lives in `/var/lib/mailcow-sentinel` and
  should not be published.

## Licence

MIT — see [LICENSE](LICENSE).
