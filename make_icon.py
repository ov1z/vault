"""Render the in-app shield logo into a Windows .ico (and a PNG preview).

Reproduces the app's shield+check mark (accent blue #3b82f6) as a filled glyph
on a dark rounded-square tile, supersampled for clean edges.
"""

from PIL import Image, ImageDraw

SS = 1024  # supersample canvas (4x of 256)
ACCENT = (59, 130, 246, 255)   # #3b82f6
TILE = (27, 27, 34, 255)       # #1b1b22
WHITE = (255, 255, 255, 255)


def build_master() -> Image.Image:
    img = Image.new("RGBA", (SS, SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # rounded-square tile
    m = int(SS * 0.06)
    d.rounded_rectangle((m, m, SS - m, SS - m), radius=int(SS * 0.22), fill=TILE)
    # faint inner border for definition
    d.rounded_rectangle((m, m, SS - m, SS - m), radius=int(SS * 0.22),
                        outline=(255, 255, 255, 22), width=max(2, SS // 340))

    # shield placement box
    sw, sh = SS * 0.46, SS * 0.52
    sx0, sy0 = SS * 0.5 - sw / 2, SS * 0.25

    def P(nx, ny):
        return (sx0 + nx * sw, sy0 + ny * sh)

    shield = [P(*p) for p in [
        (0.50, 0.00), (1.00, 0.14), (1.00, 0.52), (0.86, 0.72), (0.68, 0.90),
        (0.50, 1.00), (0.32, 0.90), (0.14, 0.72), (0.00, 0.52), (0.00, 0.14),
    ]]
    d.polygon(shield, fill=ACCENT)

    # checkmark (white, thick, round caps/joint)
    check = [P(0.30, 0.52), P(0.46, 0.70), P(0.74, 0.34)]
    lw = int(sw * 0.11)
    d.line(check, fill=WHITE, width=lw, joint="curve")
    r = lw / 2
    for (x, y) in check:  # round all three vertices
        d.ellipse((x - r, y - r, x + r, y + r), fill=WHITE)

    return img


def main() -> None:
    master = build_master()
    base = master.resize((256, 256), Image.LANCZOS)

    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    base.save("vault.ico", format="ICO", sizes=sizes)
    base.save("vault_logo.png", format="PNG")
    print("wrote vault.ico (sizes:", ", ".join(str(s[0]) for s in sizes), ")")
    print("wrote vault_logo.png (256x256 preview)")


if __name__ == "__main__":
    main()
