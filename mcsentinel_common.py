"""
Shared plumbing for mailcow-sentinel (maildigest.py and authguard.py).

Deliberately stdlib-only, and deliberately *not* a package: it sits beside the
two scripts, so `import mcsentinel_common` resolves via sys.path[0] with no
install step, no PYTHONPATH and no virtualenv.  Clone and run.

This module exists because the two tools previously duplicated their config
parsing, Redis access and ring reading -- and that duplication caused a real
bug: the ring-coverage check was fixed in one script and not the other, so IMAP
auth failures were silently undercounted by ~70% with no warning.  One copy now.

Requires Python 3.8+.
"""

import configparser
import ipaddress
import json
import os
import sqlite3
import subprocess
import sys

__version__ = "1.0.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))

CONFIG_SEARCH = (
    os.environ.get("MCSENTINEL_CONFIG"),
    "/etc/mailcow-sentinel/config.ini",
    os.path.join(SCRIPT_DIR, "config.ini"),
)

# Values with no sensible default: a tool that emails reports must never guess
# who to mail.  Note the attacker-facing side deliberately has NO required key --
# see Mailcow.valid_identities(), which derives the domain list from mailcow
# itself rather than making the operator declare it.  A forgotten config key
# that makes the tool ban *more* is not an acceptable failure mode.
REQUIRED = (
    ("digest", "mail_to"),
    ("digest", "mail_from"),
    ("digest", "hostname"),
)

SCHEMA_VERSION = 2


class ConfigError(Exception):
    pass


# ---------------------------------------------------------------- config

def load_config(path=None):
    """Locate and parse config.ini, validating required keys.

    Fails loudly and all at once -- a half-configured cron job that runs anyway
    is worse than one that refuses to start.
    """
    candidates = (path,) if path else CONFIG_SEARCH
    tried = [p for p in candidates if p]
    chosen = next((p for p in tried if os.path.isfile(p)), None)
    if not chosen:
        raise ConfigError(
            "no config file found. Looked in:\n  " + "\n  ".join(tried)
            + "\n\nFix with:\n"
              "  sudo install -D -m 0640 config.example.ini "
              "/etc/mailcow-sentinel/config.ini")

    # interpolation=None is mandatory, not stylistic: ConfigParser's default
    # BasicInterpolation treats '%' as an escape, and a bare '%' anywhere in a
    # value raises.  Percent signs turn up naturally in thresholds, log-format
    # snippets and prose, so the default would fail on plausible user input.
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(chosen)
    except configparser.Error as e:
        raise ConfigError(f"{chosen}: {e}")

    problems = [f"[{s}] {k}" for s, k in REQUIRED
                if not cp.get(s, k, fallback="").strip()
                or "example.com" in cp.get(s, k, fallback="")]
    if problems:
        raise ConfigError(
            f"{chosen} still has placeholder or missing settings:\n  "
            + "\n  ".join(problems)
            + "\n\nSee config.example.ini for what each one means.")

    cp.config_path = chosen
    return cp


def cfg_list(cp, section, option, fallback=""):
    """A multi-line or comma-separated INI value -> list of clean entries."""
    raw = cp.get(section, option, fallback=fallback) or ""
    out = []
    for line in raw.replace(",", "\n").splitlines():
        line = line.split(";")[0].strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def cfg_networks(cp, section, option, fallback=""):
    """CIDR list, parsed at load time so a typo fails now, not at 00:10."""
    nets = []
    for item in cfg_list(cp, section, option, fallback):
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError as e:
            raise ConfigError(f"[{section}] {option}: {item!r} is not a network ({e})")
    return nets


def cfg_path(cp, section, option, fallback=""):
    """Resolve a path relative to the config file, since cron has no useful cwd."""
    v = cp.get(section, option, fallback=fallback).strip()
    if not v:
        return ""
    return v if os.path.isabs(v) else os.path.join(
        os.path.dirname(getattr(cp, "config_path", ".")), v)


def in_networks(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


# ---------------------------------------------------------------- shell

def sh(cmd, timeout=240, env_extra=None):
    """Run a command, return stdout ('' on any failure).

    `env_extra` is merged over the current environment.  This is how secrets
    reach redis-cli and mysql without ever appearing in argv -- and therefore
    without appearing in the host process table, the docker daemon's audit log,
    or the container's own process table.
    """
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


# ---------------------------------------------------------------- mailcow

class Mailcow:
    """Access to a mailcow-dockerized deployment: config, containers, Redis, SQL."""

    def __init__(self, cp):
        self.dir = cp.get("mailcow", "dir", fallback="/opt/mailcow-dockerized")
        self._conf = None
        self._names = {}
        self._ring_stats = {}
        self._project = (cp.get("mailcow", "compose_project", fallback="").strip()
                         or self.conf("COMPOSE_PROJECT_NAME")
                         or os.path.basename(self.dir).lower())
        self.cert_path = (cfg_path(cp, "mailcow", "cert_path")
                          or os.path.join(self.dir, "data/assets/ssl/cert.pem"))

    # ---- mailcow.conf

    def conf(self, key, default=""):
        """Read a key out of mailcow.conf, with .env semantics.

        Docker's .env is last-wins and permits quoting, so honour both rather
        than taking the first raw match.
        """
        if self._conf is None:
            self._conf = {}
            try:
                with open(os.path.join(self.dir, "mailcow.conf")) as fh:
                    for line in fh:
                        line = line.strip()
                        if line.startswith("export "):
                            line = line[7:].lstrip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        v = v.strip()
                        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                            v = v[1:-1]
                        self._conf[k.strip()] = v      # last wins
            except OSError:
                pass
        return self._conf.get(key, default)

    # ---- containers

    def container(self, service):
        """Resolve a compose service to its real container name.

        Looked up by label rather than string-built, because compose v1 joins
        with '_' and v2 with '-', COMPOSE_PROJECT_NAME is site-specific, and a
        site may override container_name outright.  The labels are the contract.
        """
        if service in self._names:
            return self._names[service]
        out = sh(["docker", "ps",
                  "--filter", f"label=com.docker.compose.project={self._project}",
                  "--filter", f"label=com.docker.compose.service={service}",
                  "--format", "{{.Names}}"], timeout=60).strip().splitlines()
        name = out[0].strip() if out else f"{self._project}-{service}-1"
        self._names[service] = name
        return name

    def container_count(self):
        return len([l for l in sh(
            ["docker", "ps", "--filter",
             f"label=com.docker.compose.project={self._project}",
             "--format", "{{.Names}}"], timeout=60).splitlines() if l.strip()])

    def unhealthy(self):
        out = sh(["docker", "ps", "--filter",
                  f"label=com.docker.compose.project={self._project}",
                  "--format", "{{.Names}}\t{{.Status}}"], timeout=60)
        bad = []
        for line in out.splitlines():
            name, _, status = line.partition("\t")
            if "unhealthy" in status.lower() or "restarting" in status.lower():
                bad.append(name)
        return bad

    def expected_containers(self, cp, db=None):
        """How many services this deployment should be running.

        Derived from compose rather than hardcoded, so it honours the SKIP_CLAMD
        / SKIP_SOGO / SKIP_OLEFY flags that legitimately change the count.
        Cached in `meta`, so a transient compose failure cannot silently drop the
        expected count to zero and make the health check vacuous.
        """
        explicit = cp.get("mailcow", "expected_containers", fallback="auto").strip()
        if explicit.isdigit():
            return int(explicit)
        try:
            out = subprocess.run(["docker", "compose", "config", "--services"],
                                 capture_output=True, text=True, timeout=120,
                                 cwd=self.dir)
            n = len([l for l in out.stdout.splitlines() if l.strip()])
        except Exception:
            n = 0
        if n:
            if db is not None:
                meta_set(db, "expected_containers", n)
            return n
        if db is not None:
            cached = meta_get(db, "expected_containers")
            if cached and cached.isdigit():
                return int(cached)
        return 0

    # ---- redis

    def redis(self, *args, timeout=240):
        """Run redis-cli inside the redis container.

        The password is forwarded by name via `docker exec -e REDISCLI_AUTH`,
        so the value never enters any argv on either side.
        """
        return sh(["docker", "exec", "-e", "REDISCLI_AUTH",
                   self.container("redis-mailcow"), "redis-cli",
                   "--no-auth-warning", *args],
                  timeout=timeout,
                  env_extra={"REDISCLI_AUTH": self.conf("REDISPASS")})

    def ring(self, key, timeout=240):
        """Yield (ts, program, message) from a mailcow Redis ring buffer.

        Records the oldest timestamp per ring so callers can ask coverage()
        whether the ring actually reached back far enough.
        """
        out = self.redis("LRANGE", key, "0", "-1", timeout=timeout)
        oldest, count = None, 0
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                e = json.loads(line)
                ts = int(float(e.get("time", 0)))
            except (ValueError, TypeError):
                continue
            count += 1
            if oldest is None or ts < oldest:
                oldest = ts
            yield ts, e.get("program", ""), e.get("message", "")
        self._ring_stats[key] = {"oldest": oldest, "entries": count}

    def coverage(self, window_start):
        """Per-ring answer to: did this ring reach back to the window start?

        The point of reading the durable rings instead of container logs is to
        never report a partial window as if it were whole.  A ring is only as
        good as its depth, and the rings have *different* depths -- dovecot is
        chattier than postfix, so it rolls over sooner.  Checking one ring and
        speaking for both is the bug this function exists to prevent.
        """
        out = {}
        for key, st in self._ring_stats.items():
            oldest = st["oldest"]
            out[key] = {
                "entries": st["entries"],
                "oldest": oldest,
                "full": oldest is not None and oldest <= window_start,
                "missing_hours": (max(0, oldest - window_start) / 3600.0
                                  if oldest else 0.0),
            }
        return out

    # ---- mysql

    def mysql(self, query, timeout=120):
        """Run a query. Password via MYSQL_PWD, never argv."""
        return sh(["docker", "exec", "-e", "MYSQL_PWD",
                   self.container("mysql-mailcow"), "mysql",
                   "-u" + self.conf("DBUSER"), self.conf("DBNAME"),
                   "-N", "-B", "-e", query],
                  timeout=timeout,
                  env_extra={"MYSQL_PWD": self.conf("DBPASS")})

    def valid_identities(self):
        """-> (full addresses, bare local parts, active domains).

        Domains come from mailcow rather than from config on purpose.  Requiring
        the operator to declare their domain would mean a forgotten key makes
        every bare-username attempt look like a nonexistent identity -- i.e. the
        tool would ban *more* when misconfigured.  For a banning tool that is the
        wrong direction to fail in.
        """
        out = self.mysql(
            "SELECT username FROM mailbox WHERE active=1; "
            "SELECT address FROM alias WHERE active=1; "
            "SELECT CONCAT('@domain:', domain) FROM domain WHERE active=1;")
        full, domains = set(), set()
        for line in out.splitlines():
            line = line.strip().lower()
            if line.startswith("@domain:"):
                domains.add(line.split(":", 1)[1])
            elif "@" in line:
                full.add(line)
        return full, {a.split("@")[0] for a in full}, domains


# ---------------------------------------------------------------- sqlite

def db_open(path):
    """Open the shared history DB with sane concurrency settings, and migrate.

    maildigest and authguard share one file and their schedules overlap, so:
      * WAL     -- readers never block on the writer
      * timeout -- the busy handler gets a chance to do its job
      * isolation_level=None -- we manage transactions explicitly with
        BEGIN IMMEDIATE.  This matters: with sqlite3's default *deferred*
        transactions, a transaction that reads first and writes later can hit
        SQLITE_BUSY on the read->write upgrade, and the busy handler cannot
        retry that case at all, whatever busy_timeout says.  Both tools
        read-then-write, so both are exposed without this.
    """
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    c = sqlite3.connect(path, timeout=15.0, isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=15000")
    c.execute("PRAGMA synchronous=NORMAL")
    _ensure_schema(c)
    return c


def _ensure_schema(c):
    """Create every table both tools use, then apply versioned migrations.

    All tables, not just the caller's: otherwise whichever tool runs first on a
    fresh install leaves the other's tables missing, and `authguard --report`
    before the first digest dies with `no such table`.
    """
    # Individually, not via executescript(): executescript() issues an implicit
    # COMMIT before it runs, which would silently end the BEGIN IMMEDIATE below
    # and leave the migration unprotected.
    ddl = (
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
        "CREATE TABLE IF NOT EXISTS account_day ("
        " date TEXT, account TEXT, recv INT, sent INT,"
        " PRIMARY KEY (date, account))",
        "CREATE TABLE IF NOT EXISTS daily (date TEXT PRIMARY KEY, metrics TEXT)",
        "CREATE TABLE IF NOT EXISTS warn_class ("
        " cls TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, total INT)",
        "CREATE TABLE IF NOT EXISTS authguard_ban ("
        " ip TEXT PRIMARY KEY, added_ts INT, expires_ts INT,"
        " reason TEXT, detail TEXT)",
        "CREATE TABLE IF NOT EXISTS authguard_seen_ok ("
        " ip TEXT PRIMARY KEY, last_ts INT)",
        "CREATE INDEX IF NOT EXISTS ix_seen_ok_last_ts"
        " ON authguard_seen_ok(last_ts)",
        "CREATE INDEX IF NOT EXISTS ix_ban_expires"
        " ON authguard_ban(expires_ts)",
        # One row per (day, source address) that attempted authentication.
        # ~500 rows/day on a small server; pruned to a retention window by the
        # digest, so it stays a few tens of thousands at most.
        "CREATE TABLE IF NOT EXISTS attacker_day ("
        " date TEXT, ip TEXT, attempts INT, banned INT DEFAULT 0,"
        " PRIMARY KEY (date, ip))",
        "CREATE INDEX IF NOT EXISTS ix_attacker_ip ON attacker_day(ip)",
        "CREATE INDEX IF NOT EXISTS ix_attacker_date ON attacker_day(date)",
    )
    c.execute("BEGIN IMMEDIATE")
    try:
        for stmt in ddl:
            c.execute(stmt)
        ver = c.execute("PRAGMA user_version").fetchone()[0]
        if ver < 1:
            # v0 -> v1: lift the '#idcount' sentinel out of authguard_seen_ok,
            # where a count was being stored in a column named last_ts.  Carry
            # the value across so the "refuse to run if the mailbox list
            # halved" guard keeps its history instead of resetting to 0 and
            # being inert for a run.  No-ops cleanly on a fresh database.
            c.execute(
                "INSERT OR REPLACE INTO meta (key, value) "
                "SELECT 'identity_count', CAST(last_ts AS TEXT) "
                "FROM authguard_seen_ok WHERE ip='#idcount'")
            c.execute("DELETE FROM authguard_seen_ok WHERE ip='#idcount'")
        if ver < 2:
            # v1 -> v2 adds attacker_day, created by the DDL above. Nothing to
            # migrate: repeat-offender history simply starts accumulating from
            # the next run, which the digest states rather than implying it has
            # data it does not.
            pass
        if ver < SCHEMA_VERSION:
            c.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise


def meta_get(c, key, default=None):
    row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(c, key, value):
    c.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))


def die(msg, code=2):
    sys.stderr.write(msg.rstrip() + "\n")
    raise SystemExit(code)
