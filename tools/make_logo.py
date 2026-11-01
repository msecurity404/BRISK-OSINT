"""Regenerate assets/logo.svg and assets/logo.png.

PNG rendering tries cairosvg, rsvg-convert, then falls back to a built-in Pillow renderer
that draws the same design, so it works anywhere Pillow is installed.
"""
import math
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from brisk_osint import branding as b  # noqa: E402

SVG = os.path.join(ROOT, "assets", "logo.svg")
PNG = os.path.join(ROOT, "assets", "logo.png")


def hx(c):
    return tuple(int(c.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))


def lerp(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def render_pillow(scale=2):
    from PIL import Image, ImageDraw, ImageFont, ImageFilter

    W, H, cell = 1000, 620, 26
    S = scale
    img = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # background
    bg = Image.new("RGBA", (W * S, H * S))
    bd = ImageDraw.Draw(bg)
    for y in range(H * S):
        bd.line([(0, y), (W * S, y)], fill=lerp(hx("#1A0E3A"), hx(b.INK), y / (H * S)) + (255,))
    mask = Image.new("L", (W * S, H * S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, W * S - 1, H * S - 1], 38 * S, fill=255)
    img.paste(bg, (0, 0), mask)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([3 * S, 3 * S, (W - 3) * S, (H - 3) * S], 36 * S, outline=hx(b.GOLD) + (255,), width=3 * S)

    # glow
    glow = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse([(500 - 170) * S, (150 - 170) * S, (500 + 170) * S, (150 + 170) * S],
                                 fill=hx(b.PURPLE_LIGHT) + (90,))
    glow = glow.filter(ImageFilter.GaussianBlur(40 * S))
    img = Image.alpha_composite(img, glow)
    d = ImageDraw.Draw(img)

    # circuit lines
    cx, cy, R = 500, 150, 100
    gold = hx(b.GOLD) + (255,)
    for sx, dy in ((-1, -38), (1, 38)):
        d.line([(cx + sx * (R + 6)) * S, cy * S, (cx + sx * 230) * S, cy * S], fill=gold, width=3 * S)
        d.line([(cx + sx * 230) * S, cy * S, (cx + sx * 230) * S, (cy + dy) * S, (cx + sx * 300) * S, (cy + dy) * S],
               fill=gold, width=3 * S)
    for x, y, c in ((cx - 300, cy - 38, b.PURPLE_LIGHT), (cx + 300, cy + 38, b.GOLD)):
        d.ellipse([(x - 9) * S, (y - 9) * S, (x + 9) * S, (y + 9) * S], fill=hx(c) + (255,))

    # hexagon + radar
    pts = [((cx + R * math.cos(math.radians(-90 + 60 * k))) * S, (cy + R * math.sin(math.radians(-90 + 60 * k))) * S) for k in range(6)]
    d.polygon(pts, fill=hx("#150A30") + (255,), outline=hx(b.GOLD_LIGHT) + (255,), width=5 * S)
    for r in (62, 41, 20):
        d.ellipse([(cx - r) * S, (cy - r) * S, (cx + r) * S, (cy + r) * S], outline=hx(b.GOLD) + (140,), width=2 * S)
    d.line([(cx - 66) * S, cy * S, (cx + 66) * S, cy * S], fill=hx(b.GOLD) + (140,), width=2 * S)
    d.line([cx * S, (cy - 66) * S, cx * S, (cy + 66) * S], fill=hx(b.GOLD) + (140,), width=2 * S)
    d.pieslice([(cx - 62) * S, (cy - 62) * S, (cx + 62) * S, (cy + 62) * S], -85, -25, fill=hx(b.PURPLE_LIGHT) + (150,))
    a = math.radians(-25)
    d.line([cx * S, cy * S, (cx + 62 * math.cos(a)) * S, (cy + 62 * math.sin(a)) * S], fill=hx(b.GOLD_LIGHT) + (255,), width=3 * S)
    for x, y, r, c in ((cx + 30, cy - 34, 6, b.GOLD_LIGHT), (cx - 28, cy + 22, 5, b.GOLD), (cx + 12, cy + 40, 4, b.PURPLE_LIGHT), (cx, cy, 6, b.GOLD_LIGHT)):
        d.ellipse([(x - r) * S, (y - r) * S, (x + r) * S, (y + r) * S], fill=hx(c) + (255,))

    # block letters
    lw, gap = 5 * cell, cell
    total = 5 * lw + 4 * gap
    x0, y0 = (W - total) / 2, 300
    cells = []
    for li, ch in enumerate("BRISK"):
        for r, row in enumerate(b.GLYPHS[ch]):
            for c, v in enumerate(row):
                if v == "#":
                    cells.append((x0 + li * (lw + gap) + c * cell, y0 + r * cell, ch == "I"))
    size = cell - 3
    for x, y, g in cells:  # extruded shadow
        d.rounded_rectangle([(x + 8) * S, (y + 8) * S, (x + 8 + size) * S, (y + 8 + size) * S], 5 * S,
                            fill=hx(b.PURPLE_DARK if g else b.GOLD_DARK) + (255,))
    for x, y, g in cells:  # vertical-gradient faces
        top, mid, bot = ((b.GOLD_LIGHT, b.GOLD, b.GOLD_DARK) if g else (b.PURPLE_LIGHT, b.PURPLE, b.PURPLE_DARK))
        tile = Image.new("RGBA", (size * S, size * S))
        td = ImageDraw.Draw(tile)
        for yy in range(size * S):
            t = yy / (size * S)
            col = lerp(hx(top), hx(mid), t / .45) if t < .45 else lerp(hx(mid), hx(bot), (t - .45) / .55)
            td.line([(0, yy), (size * S, yy)], fill=col + (255,))
        m = Image.new("L", (size * S, size * S), 0)
        ImageDraw.Draw(m).rounded_rectangle([0, 0, size * S - 1, size * S - 1], 5 * S, fill=255)
        img.paste(tile, (int(x * S), int(y * S)), m)
        d.rounded_rectangle([(x + 3) * S, (y + 2) * S, (x + size - 3) * S, (y + 7) * S], 2 * S, fill=(255, 255, 255, 56))
    d = ImageDraw.Draw(img)

    # divider + text
    yb = y0 + 5 * cell + 36
    d.rounded_rectangle([x0 * S, yb * S, (x0 + total) * S, (yb + 4) * S], 2 * S, fill=hx(b.GOLD) + (255,))

    def font(sz, bold=False):
        for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                  "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"):
            if os.path.exists(p):
                return ImageFont.truetype(p, sz * S)
        return ImageFont.load_default()

    def spaced(text, y, sz, color, spacing, bold):
        f = font(sz, bold)
        widths = [d.textlength(ch, font=f) for ch in text]
        tw = sum(widths) + spacing * S * (len(text) - 1)
        x = W * S / 2 - tw / 2
        for ch, w in zip(text, widths):
            d.text((x, y * S), ch, font=f, fill=color)
            x += w + spacing * S

    spaced("OSINT RECON FRAMEWORK", y0 + 5 * cell + 58, 28, hx(b.GOLD) + (255,), 7, True)
    spaced(f"Developed by {b.AUTHOR}", y0 + 5 * cell + 108, 20, hx("#CFC3EA") + (255,), 2, False)
    return img


def main():
    os.makedirs(os.path.dirname(SVG), exist_ok=True)
    with open(SVG, "w", encoding="utf-8") as fh:
        fh.write(b.logo_svg())
    print("wrote", SVG)
    try:
        import cairosvg  # type: ignore
        cairosvg.svg2png(url=SVG, write_to=PNG, output_width=2000)
        print("wrote", PNG, "(cairosvg)")
        return
    except Exception:
        pass
    if shutil.which("rsvg-convert") and subprocess.run(["rsvg-convert", "-w", "2000", "-o", PNG, SVG]).returncode == 0:
        print("wrote", PNG, "(rsvg-convert)")
        return
    try:
        render_pillow(2).save(PNG)
        print("wrote", PNG, "(Pillow)")
    except Exception as e:  # noqa: BLE001
        print("PNG skipped:", e)


if __name__ == "__main__":
    main()
