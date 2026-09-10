#!/bin/sh
# mailcow-sentinel installer. POSIX sh, idempotent, safe to re-run for upgrades.
#
# Never clobbers an existing config or database.

set -eu

CODE_DIR=/opt/mailcow-sentinel
CONF_DIR=/etc/mailcow-sentinel
STATE_DIR=/var/lib/mailcow-sentinel
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: these tools read mailcow.conf (0600) and the docker socket" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    echo "Removing $CODE_DIR. Leaving $CONF_DIR and $STATE_DIR alone --"
    echo "delete those by hand if you really want the config and history gone."
    rm -rf "$CODE_DIR"
    echo "Remember to remove the cron entries."
    exit 0
fi

echo "Installing to $CODE_DIR"
install -d -m 0755 "$CODE_DIR"
install -m 0750 "$SRC/maildigest.py" "$SRC/authguard.py" "$CODE_DIR/"
install -m 0640 "$SRC/mcsentinel_common.py" "$CODE_DIR/"

install -d -m 0750 "$CONF_DIR"
install -d -m 0750 "$STATE_DIR"

NEW_CONF=0
if [ ! -f "$CONF_DIR/config.ini" ]; then
    install -m 0640 "$SRC/config.example.ini" "$CONF_DIR/config.ini"
    NEW_CONF=1
fi
if [ ! -f "$CONF_DIR/llm_prompt.txt" ]; then
    install -m 0640 "$SRC/llm_prompt.example.txt" "$CONF_DIR/llm_prompt.txt"
fi

echo
if [ "$NEW_CONF" = 1 ]; then
    cat <<EOF
Installed. Now edit the three required settings:

    $EDITOR $CONF_DIR/config.ini
        [digest] mail_to, mail_from, hostname

then check it:

    $CODE_DIR/maildigest.py --check-config
    $CODE_DIR/authguard.py  --check-config
EOF
else
    echo "Installed. Existing config at $CONF_DIR/config.ini left untouched."
    echo "Re-run --check-config in case new settings were added."
fi

cat <<EOF

Try it without changing anything:

    $CODE_DIR/authguard.py --dry-run
    $CODE_DIR/maildigest.py --date \$(date -d yesterday +%F) --stdout --no-llm

When you are happy, add to root's crontab (see examples/crontab):

    12 0 * * * $CODE_DIR/maildigest.py >> /var/log/mailcow_digest.log 2>&1
    */5 * * * * $CODE_DIR/authguard.py  >> /var/log/mailcow_authguard.log 2>&1

Cron entries are deliberately NOT installed for you: authguard bans real
addresses, so it should not start doing that as a side effect of an install.
EOF
