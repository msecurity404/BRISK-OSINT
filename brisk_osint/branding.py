"""Brisk branding: terminal banner + SVG block logo (purple & gold)."""
from __future__ import annotations

import math
import os
import sys

PURPLE = "#5B2A9E"
PURPLE_DARK = "#2D1457"
PURPLE_LIGHT = "#9B6BE8"
GOLD = "#E5A91B"
GOLD_DARK = "#9A6A06"
GOLD_LIGHT = "#FFD76A"
INK = "#0D0820"

AUTHOR = "Eng. Malek Al-astal"

# 5x5 pixel block font
GLYPHS = {
    "B": ["####.", "#...#", "####.", "#...#", "####."],
    "R": ["####.", "#...#", "####.", "#..#.", "#...#"],
    "I": ["#####", "..#..", "..#..", "..#..", "#####"],
    "S": [".####", "#....", ".###.", "....#", "####."],
    "K": ["#...#", "#..#.", "###..", "#..#.", "#...#"],
}


def _rgb(hex_: str) -> tuple[int, int, int]:
    h = hex_.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def paint(text: str, hex_: str, color: bool = True, bold: bool = False) -> str:
    if not color:
        return text
    r, g, b = _rgb(hex_)
    return f"\x1b[{'1;' if bold else ''}38;2;{r};{g};{b}m{text}\x1b[0m"


def use_color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def banner(version: str, color: bool = True) -> str:
    word = "BRISK"
    lines = []
    for r in range(5):
        row = ""
        for i, ch in enumerate(word):
            seg = "".join("██" if c == "#" else "  " for c in GLYPHS[ch][r])
            hexc = GOLD if ch == "I" else PURPLE_LIGHT
            row += paint(seg, hexc, color, bold=True) + "  "
        lines.append("   " + row.rstrip())
    bar = "   " + paint("▀" * 58, GOLD, color)
    sub = "   " + paint("O S I N T   R E C O N   F R A M E W O R K", GOLD_LIGHT, color, bold=True)
    meta = "   " + paint(f"v{version}  •  Developed by {AUTHOR}", "#CFC3EA", color)
    warn = "   " + paint("For authorized security assessment & brand protection only.", "#8F83AD", color)
    return "\n" + "\n".join(lines + [bar, sub, meta, warn]) + "\n"


def logo_svg() -> str:
    cell = 26
    gap = cell
    word = "BRISK"
    lw = 5 * cell
    total = 5 * lw + 4 * gap
    W, H = 1000, 620
    x0 = (W - total) / 2
    y0 = 300

    shadows, faces = [], []
    for li, ch in enumerate(word):
        lx = x0 + li * (lw + gap)
        gold = ch == "I"
        for r, row in enumerate(GLYPHS[ch]):
            for c, v in enumerate(row):
                if v != "#":
                    continue
                x, y = lx + c * cell, y0 + r * cell
                size = cell - 3
                shadows.append(
                    f'<rect x="{x + 8:.1f}" y="{y + 8:.1f}" width="{size}" height="{size}" rx="5" '
                    f'fill="{PURPLE_DARK if gold else GOLD_DARK}"/>'
                )
                faces.append(
                    f'<rect x="{x:.1f}" y="{y:.1f}" width="{size}" height="{size}" rx="5" '
                    f'fill="url(#{"gg" if gold else "gp"})"/>'
                    f'<rect x="{x + 3:.1f}" y="{y + 2:.1f}" width="{size - 6}" height="5" rx="2.5" '
                    f'fill="#fff" opacity=".22"/>'
                )

    cx, cy, R = 500, 150, 100
    hexpts = " ".join(
        f"{cx + R * math.cos(math.radians(-90 + 60 * k)):.1f},{cy + R * math.sin(math.radians(-90 + 60 * k)):.1f}"
        for k in range(6)
    )
    rr = 62
    a1, a2 = math.radians(-85), math.radians(-25)
    sweep = (
        f"M{cx} {cy} L{cx + rr * math.cos(a1):.1f} {cy + rr * math.sin(a1):.1f} "
        f"A{rr} {rr} 0 0 1 {cx + rr * math.cos(a2):.1f} {cy + rr * math.sin(a2):.1f} Z"
    )

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="Brisk OSINT">
<defs>
  <linearGradient id="gp" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{PURPLE_LIGHT}"/><stop offset=".45" stop-color="{PURPLE}"/><stop offset="1" stop-color="{PURPLE_DARK}"/></linearGradient>
  <linearGradient id="gg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{GOLD_LIGHT}"/><stop offset=".5" stop-color="{GOLD}"/><stop offset="1" stop-color="{GOLD_DARK}"/></linearGradient>
  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#1A0E3A"/><stop offset="1" stop-color="{INK}"/></linearGradient>
  <linearGradient id="bd" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{GOLD_LIGHT}"/><stop offset=".5" stop-color="{PURPLE_LIGHT}"/><stop offset="1" stop-color="{GOLD}"/></linearGradient>
  <radialGradient id="glow" cx=".5" cy=".5" r=".5"><stop offset="0" stop-color="{PURPLE_LIGHT}" stop-opacity=".45"/><stop offset="1" stop-color="{PURPLE_LIGHT}" stop-opacity="0"/></radialGradient>
  <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" fill="none" stroke="#ffffff" stroke-opacity=".035"/></pattern>
</defs>
<rect width="{W}" height="{H}" rx="38" fill="url(#bg)"/>
<rect width="{W}" height="{H}" rx="38" fill="url(#grid)"/>
<rect x="3" y="3" width="{W - 6}" height="{H - 6}" rx="36" fill="none" stroke="url(#bd)" stroke-width="3"/>
<circle cx="{cx}" cy="{cy}" r="170" fill="url(#glow)"/>
<g stroke="{GOLD}" stroke-width="3" stroke-linecap="round" opacity=".9">
  <path d="M{cx - R - 6} {cy} H{cx - 230}"/><path d="M{cx + R + 6} {cy} H{cx + 230}"/>
  <path d="M{cx - 230} {cy} V{cy - 38} H{cx - 300}" fill="none"/><path d="M{cx + 230} {cy} V{cy + 38} H{cx + 300}" fill="none"/>
</g>
<circle cx="{cx - 300}" cy="{cy - 38}" r="9" fill="{PURPLE_LIGHT}"/><circle cx="{cx + 300}" cy="{cy + 38}" r="9" fill="{GOLD}"/>
<polygon points="{hexpts}" fill="#150A30" stroke="url(#bd)" stroke-width="5" stroke-linejoin="round"/>
<g fill="none" stroke="{GOLD}" stroke-opacity=".55" stroke-width="2">
  <circle cx="{cx}" cy="{cy}" r="62"/><circle cx="{cx}" cy="{cy}" r="41"/><circle cx="{cx}" cy="{cy}" r="20"/>
  <path d="M{cx - 66} {cy} H{cx + 66} M{cx} {cy - 66} V{cy + 66}"/>
</g>
<path d="{sweep}" fill="{PURPLE_LIGHT}" fill-opacity=".55"/>
<path d="M{cx} {cy} L{cx + rr * math.cos(a2):.1f} {cy + rr * math.sin(a2):.1f}" stroke="{GOLD_LIGHT}" stroke-width="3" stroke-linecap="round"/>
<circle cx="{cx + 30}" cy="{cy - 34}" r="6" fill="{GOLD_LIGHT}"/><circle cx="{cx - 28}" cy="{cy + 22}" r="5" fill="{GOLD}"/><circle cx="{cx + 12}" cy="{cy + 40}" r="4" fill="{PURPLE_LIGHT}"/>
<circle cx="{cx}" cy="{cy}" r="6" fill="{GOLD_LIGHT}"/>
<g>{"".join(shadows)}</g>
<g>{"".join(faces)}</g>
<rect x="{x0:.0f}" y="{y0 + 5 * cell + 36}" width="{total:.0f}" height="4" rx="2" fill="url(#bd)"/>
<text x="{W / 2}" y="{y0 + 5 * cell + 86}" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="30" font-weight="700" letter-spacing="9" fill="{GOLD}">OSINT RECON FRAMEWORK</text>
<text x="{W / 2}" y="{y0 + 5 * cell + 130}" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="21" letter-spacing="2" fill="#CFC3EA">Developed by {AUTHOR}</text>
</svg>'''


if __name__ == "__main__":
    print(banner("1.0.0", use_color()))
