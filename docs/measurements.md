# How the numbers in the README were produced

All figures come from **one small mailcow server**, over a **41.2-hour window**
ending 2026-09-10, read out of mailcow's own Redis ring buffers. One server is
not a study. Treat the numbers as an illustration of a failure mode that is
structural, not as constants that will reproduce on your host.

## Source data

```
POSTFIX_MAILLOG   10,003 entries   oldest 2026-09-08 23:43
DOVECOT_MAILLOG   10,000 entries   oldest 2026-09-09 20:12
```

An auth failure is a `SASL … authentication failed` line in `POSTFIX_MAILLOG`
(submission and smtps) or a `Password mismatch` line in `DOVECOT_MAILLOG` (IMAP),
excluding `watchdog@invalid`, which is mailcow's own liveness probe.

```
auth failures        669
distinct source IPs  326
successful auths       3   (all accounted for: two internal, one known app)
```

Note the two rings have very different depths — dovecot is chattier, so its
10,000 entries span far less wall-clock time. **This is why coverage is reported
per ring.** An earlier version of the digest tracked coverage from the postfix
ring only and silently undercounted IMAP failures by ~70% with no warning: the
same day reported 430 failures when run early and 347 when run hours later, both
without complaint. That bug is the reason `! COVERAGE` exists.

## Attempts per IP — the distribution that decides everything

```
  1 attempt :  162 IPs      <- 50%. No per-IP threshold can ever catch these.
  2 attempts:   88 IPs
  3 attempts:   25 IPs
  4 attempts:   33 IPs
  5+        :   18 IPs      (max observed: 16)
```

## Simulating the policies

Each policy was replayed over the same event stream with a sliding window per
key, banning when the count reached the threshold, then suppressing that key for
a 30-minute ban period before it could accumulate again — matching
`netfilter-mailcow`'s behaviour. "Attempts stopped" counts attempts occurring
*after* that key's first ban.

| policy | bans | attempts stopped |
|---|---:|---:|
| 3 in 600 s *(stock)* | 7 | 4 |
| 3 in 1 h | 12 | 18 |
| 3 in 24 h | 86 | 103 |
| 2 in 24 h | 223 | 178 |
| 2 in 1 h | 165 | 103 |
| 3 in 24 h, aggregated to `/24` | 91 | 113 |

The `/24` row is the interesting negative result: aggregating to networks caught
**91 versus 86**, i.e. almost nothing. This botnet does not cluster in subnets, so
netban buys ~5 extra bans in exchange for banning every innocent neighbour of a
compromised host. Rejected.

### Collateral check

No policy above banned an IP that had also authenticated successfully — but that
is weak reassurance, because only three addresses ever authenticated successfully
in the window. The real collateral risk is a client with a **stale password**,
which by definition never succeeds. That is why the comparison table's decisive
column is "can it ban a client with a stale password?" rather than a measured
false-positive count: the dangerous case is one this dataset cannot contain.

Single-mailbox IPs with 4 attempts each were inspected by hand. They are
indistinguishable in shape from a misconfigured client — same volume, same single
target, differing only in geography, which is not something to ban on.

## The two signals

```
IPs trying >= 2 distinct identities   79 IPs   310 attempts
IPs touching a nonexistent identity   55 IPs   154 attempts
combined (union)                     111 IPs   351 attempts   (34% of IPs, 52% of attempts)
```

Identities are canonicalised before counting, so `alice` and `alice@example.com`
are one identity rather than two — without that, a bot alternating between the
bare and qualified form of a *single* mailbox would trip the "2 distinct
identities" rule on its own, and the safety property would be lost.

Simulating the firing order: 413 attempts arrive before the rule has enough
evidence to fire, and 145 would have been blocked afterwards. The gap between 351
"covered" and 145 "blocked" is the cost of needing to see a second identity before
acting.

## Reproducing this on your own server

Nothing here needs the tool installed:

```bash
RP=$(grep -oP '(?<=^REDISPASS=).*' /opt/mailcow-dockerized/mailcow.conf)
docker exec -e REDISCLI_AUTH="$RP" <redis-container> redis-cli --no-auth-warning \
    LRANGE POSTFIX_MAILLOG 0 -1 > postfix.json
```

Each entry is one JSON object per line: `{"time","program","priority","message"}`,
with `time` a Unix epoch as a string. Count attempts per source IP and look at the
distribution. If most of your attackers knock once, a per-IP threshold is not
going to help you either.
