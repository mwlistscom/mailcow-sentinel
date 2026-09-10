# Tuning

Every default was measured on one small mailcow server: roughly 150 messages/day
inbound, near-zero outbound, five active mailboxes, ~250 log lines/hour. They are
a starting point, not universal constants. The failure mode of leaving them too
low is worse than it sounds — a digest that says ATTENTION every morning is a
digest you stop opening, which puts you back where you started.

Run for a week before changing anything. The `BASELINE building — n/7 days`
line tells you when the per-account deltas and new-warning detection wake up.

## `[digest]`

| key | default | what it means | when to change |
|---|---:|---|---|
| `th_auth_fail` | 50 | failed AUTH/day before the digest calls it credential stuffing | Raise on any server with a public MX and real traffic. 50/day is *quiet*; a busy host sees thousands and should probably sit at 500–2000, or the flag never clears. |
| `th_deferred` | 5 | deferred messages before ATTENTION | Raise if you relay through a flaky upstream. Deferrals are normal in bursts; a persistent nonzero count is the real signal. |
| `th_queue` | 20 | queue depth before ATTENTION | Raise on a busy relay. On a family server anything above zero for a whole day is worth a look. |
| `th_sent_spike` | 25 | external sends by one account before CRITICAL | **The compromise tripwire.** Set it just above your busiest legitimate sender's daily peak. Too high and a compromised mailbox sends all night unnoticed; too low and your newsletter trips it. Also gated on 3× the account's own 7-day baseline, so it will not fire on a new account with no history. |
| `th_cert_days` | 21 | days before expiry to start warning | Match your renewal lead time. If something automated renews at 30 days, 21 gives you a week of "it did not work" warning. |
| `baseline_days` | 7 | history window for per-account deltas and "new" warning classes | Longer is steadier but slower to notice a genuine change. 7 matches a weekly traffic rhythm; 14 suits a server with strong weekday/weekend swings. |
| `chart_days` | 30 | days in the attached HTML chart | Cosmetic. |
| `trusted_auth` | loopback + docker bridge | networks from which authenticated submission is unremarkable | Add nothing you do not control. This is the list that decides whether a successful login is reported. |

### `[auth_allow]`

Each entry suppresses what would otherwise be a **daily CRITICAL**, so it is the
most dangerous section in the file. One line per mailbox:

```ini
[auth_allow]
app@example.com = webhost.example.net
```

Keep it short, and delete entries the moment an integration retires — the point
is that an unexpected login on that mailbox becomes loud again. The digest still
prints allowed external senders under `OK`, so they stay visible rather than
disappearing.

## `[authguard]`

| key | default | what it means | when to change |
|---|---:|---|---|
| `lookback_hours` | 24 | evidence window for the two signals | Bounded in practice by mailcow's Redis ring depth — a chatty dovecot can mean the ring only holds ~18 h whatever you set here. The digest's `! COVERAGE` line tells you when that is biting. |
| `ban_ttl_days` | 7 | how long a ban lasts | mailcow's denylist has no expiry of its own, so this is the only thing preventing permanent bans on reassigned residential addresses. Longer is not obviously better. |
| `max_list` | 5000 | cap on live entries | A safety rail, not a tuning knob. If you hit it, something is wrong. |
| `seen_ok_retention_days` | 30 | how long a successful login exempts an address | This is what protects a returning legitimate user. Shorten only if you understand that consequence. |
| `never_ban` | RFC1918 + loopback | never banned, whatever the logs say | **Add any VPN or tunnel that terminates into your mail path.** A tunnel gateway aggregates many users behind one address and looks exactly like a single very busy attacker. This is the most likely way to cause yourself an outage. |

## What is deliberately not configurable

**The two signals themselves.** "≥ 2 distinct identities" is not a threshold you
can raise to 3 — the moment it is 3, a bot alternating between two mailboxes walks
free, and the property that makes the rule safe (a real client cannot produce it)
is gone. It is a structural claim, not a sensitivity setting.

**Your mail domains.** Read from mailcow's `domain` table. A stale config key here
would make every bare-username attempt look like a nonexistent identity — the tool
would ban *more* when misconfigured, which is the wrong direction to fail in.

## Sanity checks

```bash
# what would be banned right now, changing nothing
authguard.py --dry-run

# what it currently holds, with expiry dates
authguard.py --report

# re-render any past day without mailing it
maildigest.py --date 2026-09-09 --stdout --no-llm
```

If `--dry-run` proposes something you recognise, that is the bug this command
exists to catch — check `never_ban` and `[auth_allow]` before doing anything else.
