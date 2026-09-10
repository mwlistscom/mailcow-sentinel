#!/usr/bin/env python3
"""Render examples/sample-digest.txt as a terminal-style SVG for the README.

    python3 docs/img/render.py examples/sample-digest.txt docs/img/digest.svg       dark
    python3 docs/img/render.py examples/sample-digest.txt docs/img/digest-light.svg light

Regenerate whenever the sample changes, so the image cannot drift from the text.
Stdlib only, like everything else here. Character positions are computed from a
fixed monospace advance width (CW), so column alignment in the source survives.
"""
import html
import re
import sys

SRC, OUT = sys.argv[1], sys.argv[2]
THEME = sys.argv[3] if len(sys.argv) > 3 else "dark"
lines = open(SRC).read().rstrip("\n").split("\n")

FS, CW, LH = 13, 7.81, 19          # font-size, monospace char width, line height
PAD_X, TITLEBAR, PAD_TOP, PAD_BOT = 22, 34, 14, 18
W = 830
H = TITLEBAR + PAD_TOP + len(lines) * LH + PAD_BOT

THEMES = {
    # Dark reads as a terminal. Light reads as paper -- note it is NOT the dark
    # palette lightened: the accents are re-picked to hold >= 4.5:1 against a
    # near-white ground, which amber in particular does not do if you simply
    # reuse the dark value.
    "dark": {
        "bg":     "#0f1319",
        "chrome": "#171c24",
        "line":   "#232a35",
        "dot":    "#2b323d",
        "text":   "#d6deeb",
        "dim":    "#7a8598",
        "strong": "#ffffff",
        "bad":    "#ff8b8b",
        "good":   "#6ede8a",
        "warn":   "#ffcc5c",
        "key":    "#8fb6e8",
        "bar":    "#3d6ea8",
    },
    "light": {
        "bg":     "#fdfdfc",
        "chrome": "#f0f2f6",
        "line":   "#e2e6ed",
        "dot":    "#d3d8e2",
        "text":   "#1f2430",
        "dim":    "#67717f",
        "strong": "#0b0e14",
        "bad":    "#b3261e",
        "good":   "#0f7b2f",
        "warn":   "#8a5a00",
        "key":    "#1f5fa8",
        "bar":    "#6a93c8",   # 3.12:1 -- decorative, but must stay visible
    },
}
C = THEMES[THEME]

KEYS = ("VERDICT", "FLOW", "ACCOUNTS", "REJECTS", "NEW", "TRIAGE", "BASELINE", "OK")


def spans(line):
    """-> list of (text, colour, bold). Keeps character positions exact."""
    if not line.strip():
        return []
    # Subject line
    if line.startswith("Subject:"):
        return [("Subject:", C["dim"], False),
                (line[8:], C["strong"], True)]
    # continuation of the subject
    if line.startswith("         alice@"):
        return [(line, C["strong"], True)]
    # alert rows
    if line.startswith("! "):
        head = line[:11]
        return [(head, C["bad"], True), (line[11:], C["text"], False)]
    # trailing footer
    if line.startswith("--"):
        return [(line, C["dim"], False)]
    # section keys
    for k in KEYS:
        if line.startswith(k):
            colour = C["good"] if k == "OK" else C["key"]
            rest = line[len(k):]
            out = [(k, colour, True)]
            # highlight the verdict word itself
            if "ATTENTION" in rest:
                i = rest.index("ATTENTION")
                out += [(rest[:i], C["text"], False),
                        ("ATTENTION", C["bad"], True),
                        (rest[i + 9:], C["text"], False)]
            else:
                out.append((rest, C["text"], False))
            return out
    # account rows: split the ### bar off so it can be tinted
    m = re.match(r"^(.*?)(\s)(#+)\s*$", line)
    if m:
        return [(m.group(1) + m.group(2), C["text"], False),
                (m.group(3), C["bar"], False)]
    # combolist artefact and the advice under it
    if "httpswww" in line or line.strip().startswith(("->", "check those", "breach-dump")):
        return [(line, C["warn"], False)]
    if "breach-dump" in line:
        return [(line, C["warn"], False)]
    return [(line, C["text"], False)]


rows = []
y = TITLEBAR + PAD_TOP + FS
for line in lines:
    x = PAD_X
    for text, colour, bold in spans(line):
        if text:
            weight = ' font-weight="600"' if bold else ""
            rows.append(
                f'<text x="{x:.1f}" y="{y:.0f}" fill="{colour}"{weight} '
                f'xml:space="preserve">{html.escape(text)}</text>')
            x += len(text) * CW
    y += LH

dots = "".join(
    f'<circle cx="{22 + i * 17}" cy="17" r="5.5" fill="{C['dot']}"/>' for i in range(3))

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H:.0f}"
     viewBox="0 0 {W} {H:.0f}" role="img"
     aria-label="A mailcow-sentinel daily digest email, 37 lines, showing a
     verdict of ATTENTION for credential stuffing, mail flow totals, per-mailbox
     volumes, an authentication attack summary and a health line.">
  <rect width="{W}" height="{H:.0f}" rx="10" fill="{C['bg']}"/>
  <path d="M0 10a10 10 0 0 1 10-10h{W - 20}a10 10 0 0 1 10 10v{TITLEBAR - 10}H0z"
        fill="{C['chrome']}"/>
  <line x1="0" y1="{TITLEBAR}" x2="{W}" y2="{TITLEBAR}" stroke="{C['line']}"/>
  {dots}
  <text x="76" y="22" fill="{C['dim']}" font-size="11.5"
        font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
        letter-spacing="0.08em">MAILCOW-SENTINEL &#183; DAILY DIGEST</text>
  <g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
     font-size="{FS}">
{chr(10).join("    " + r for r in rows)}
  </g>
</svg>
'''
open(OUT, "w").write(svg)
print(f"{OUT}: {THEME}, {W}x{H:.0f}, {len(lines)} lines, {len(svg)} bytes")
