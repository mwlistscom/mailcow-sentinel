#!/usr/bin/env python3
"""Render the attached HTML chart to PNGs for the README, from fixture data.

    python3 docs/img/render-chart.py            # writes chart.png and chart-light.png

Drives maildigest.render_html() directly, so what you see is the real generated
page rather than a mock-up -- only the data is synthetic. Needs `wkhtmltoimage`
(Debian/Ubuntu: `apt install wkhtmltopdf`).

The page itself picks light or dark from the viewer's `prefers-color-scheme`.
wkhtmltoimage has no way to set that, so each theme is captured by pinning the
palette with one extra stylesheet -- the same values the media query would apply,
so layout and content are untouched.
"""

import datetime as dt
import os
import shutil
import subprocess
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

import maildigest  # noqa: E402

DAYS = 30
END = dt.date(2026, 9, 9)

# Synthetic volumes. Deliberately flat-ish inbound with near-zero outbound,
# because that IS the point: against a zero baseline any sustained outbound from
# a mailbox is obvious without tuning a threshold.
ACCOUNTS = {
    "alice@example.com": (48, 72),
    "dave@example.com":  (24, 40),
    "carol@example.com": (18, 31),
    "bob@example.com":   (11, 22),
    "erin@example.com":  (8, 18),
}
SENDER = "app@example.com"          # a webhost integration, 1-2/day

# One mailbox goes bad in the last three days. Included deliberately: a chart of
# six healthy mailboxes is six rows of near-identical blue, and says nothing
# about what the chart is FOR. This is what the tripwire actually looks like --
# against a flat-zero outbound baseline, no threshold tuning is needed to see it.
COMPROMISED = "carol@example.com"
SPIKE = {2: 40, 1: 150, 0: 210}     # days-before-END -> messages sent
                                    # kept modest so the inbound bars stay
                                    # legible beside it; the point is the
                                    # shape, not the magnitude


def series():
    """Deterministic pseudo-random volumes -- no RNG seed drift between runs."""
    out = defaultdict(dict)
    for i in range(DAYS):
        d = (END - dt.timedelta(days=DAYS - 1 - i)).isoformat()
        for n, (acct, (lo, hi)) in enumerate(ACCOUNTS.items()):
            # cheap deterministic wobble, plus a weekend dip
            wob = ((i * 7 + n * 13) % (hi - lo + 1))
            weekend = 0.55 if (END - dt.timedelta(days=DAYS - 1 - i)).weekday() >= 5 else 1.0
            out[d][acct] = {"recv": int((lo + wob) * weekend), "sent": 0}
        out[d][SENDER] = {"recv": 0, "sent": 1 + (i % 2)}
        back = DAYS - 1 - i
        if back in SPIKE:
            out[d][COMPROMISED]["sent"] = SPIKE[back]
    return out


PIN = {
    "dark": ("--bg:#0c0f14;--card:#151a22;--ink:#f1f4f9;--dim:#98a1b1;"
             "--rule:#262d38;--s1:#3987e5;--s2:#d95926"),
    "light": ("--bg:#f4f6f9;--card:#fff;--ink:#101520;--dim:#666f7e;"
              "--rule:#dfe4ec;--s1:#2a78d6;--s2:#eb6834"),
}


def main():
    maildigest.CFG = {"hostname": "mail.example.com"}
    doc = maildigest.render_html(END.isoformat(), {}, series(), "OK")

    for theme, pin in PIN.items():
        html = doc.replace("</style>", f":root{{{pin}}}</style>")
        suffix = "" if theme == "dark" else "-light"
        tmp = os.path.join(HERE, f".chart{suffix}.html")
        png = os.path.join(HERE, f"chart{suffix}.png")
        with open(tmp, "w") as fh:
            fh.write(html)
        subprocess.run(
            ["wkhtmltoimage", "--enable-local-file-access", "--width", "900",
             "--quality", "94", "--format", "png", tmp, png],
            check=True, capture_output=True)
        os.unlink(tmp)
        raw = os.path.getsize(png)

        # wkhtmltoimage writes an essentially uncompressed 32-bit PNG -- 3.4 MB
        # for this page. Palette-reduce and recompress; a flat-colour chart loses
        # nothing visible and lands around 16 KB. Skipped silently if the tools
        # are absent, so the script still works without them.
        for cmd in (["pngquant", "--quality=70-96", "--speed", "1",
                     "--force", "--output", png, png],
                    ["optipng", "-quiet", "-o5", png]):
            if shutil.which(cmd[0]):
                subprocess.run(cmd, check=False, capture_output=True)

        now = os.path.getsize(png)
        print(f"  {os.path.basename(png):<17} {raw // 1024:>5} KB -> "
              f"{now // 1024:>3} KB  ({theme})")


if __name__ == "__main__":
    main()
