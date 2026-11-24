"""Regenerates assets/header_bg.png and assets/hirz_logo_soft.png (run once; needs Pillow)."""
import math, random
from PIL import Image, ImageDraw, ImageFilter

HERE = __import__("pathlib").Path(__file__).resolve().parent

# 1. navy band with a faint cyan node network, echoing the Hirz slide
W, H = 2480, 472                      # 210 x 40 mm at 300 dpi
bg = Image.new("RGB", (W, H))
px = bg.load()
for y in range(H):
    t = y / H
    c = (int(11 + 6 * t), int(22 + 22 * t), int(41 + 34 * t))
    for x in range(W):
        px[x, y] = c
glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
d = ImageDraw.Draw(glow)
rnd = random.Random(42)
nodes = [(rnd.uniform(0, W), H * (0.35 + 0.65 * rnd.random() ** 0.6)) for _ in range(140)]
for i, (x1, y1) in enumerate(nodes):
    for x2, y2 in nodes[i + 1:]:
        dist = math.hypot(x2 - x1, y2 - y1)
        if dist < 150:
            a = int(70 * (1 - dist / 150) * (y1 / H))
            d.line([(x1, y1), (x2, y2)], fill=(56, 189, 248, a), width=2)
for x, y in nodes:
    r = rnd.uniform(2, 5)
    d.ellipse([x - r, y - r, x + r, y + r], fill=(125, 211, 252, int(200 * y / H)))
blur = glow.filter(ImageFilter.GaussianBlur(6))
bg = Image.alpha_composite(bg.convert("RGBA"), blur)
bg = Image.alpha_composite(bg, glow).convert("RGB")
bg.save(HERE / "header_bg.png", optimize=True)

# 2. logo with soft edges so it blends into the band (no visible square)
logo = Image.open(HERE / "hirz_logo.png").convert("RGBA")
w, h = logo.size
mask = Image.new("L", (w, h), 0)
m = mask.load()
for y in range(h):
    for x in range(w):
        dx, dy = (x - w / 2) / (w / 2), (y - h / 2) / (h / 2)
        r = math.hypot(dx, dy)
        m[x, y] = int(255 * max(0.0, min(1.0, (1.08 - r) / 0.28)))
logo.putalpha(mask)
logo.save(HERE / "hirz_logo_soft.png", optimize=True)
print("ok")
