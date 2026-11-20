#!/usr/bin/env python3
"""Generate the Assay icon set with no third-party dependencies.

Tauri expects a specific set of PNG sizes plus a Windows `.ico`. Rather than
pull in Pillow for a handful of flat-shaded images, this script emits PNGs
directly (IHDR/IDAT/IEND chunks, zlib-compressed scanlines) and wraps the same
pixels in an ICO container. The result is byte-reproducible and reviewable.

Usage:
    python scripts/make_icons.py [--out assets/icons]
"""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

# Brand palette, matching `ui/src/styles/app.css`.
GRADIENT_START = (143, 121, 255)  # #8f79ff
GRADIENT_END = (76, 194, 255)     # #4cc2ff
BACKGROUND = (16, 21, 30)         # --surface
TRANSPARENT = (0, 0, 0, 0)


def lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return (
        round(a[0] + (b[0] - a[0]) * t),
        round(a[1] + (b[1] - a[1]) * t),
        round(a[2] + (b[2] - a[2]) * t),
    )


def coverage(x: float, y: float, w: float, h: float, radius: float) -> bool:
    """True when (x, y) is inside a rounded rectangle centred at (w/2, h/2)."""
    cx, cy = w / 2, h / 2
    dx = abs(x - cx) - (cx - radius)
    dy = abs(y - cy) - (cy - radius)
    if dx <= 0 or dy <= 0:
        return abs(x - cx) <= cx and abs(y - cy) <= cy
    return dx * dx + dy * dy <= radius * radius


def diamond(x: float, y: float, cx: float, cy: float, half_w: float, half_h: float) -> bool:
    """True when (x, y) is inside a rhombus centred at (cx, cy)."""
    return abs(x - cx) / half_w + abs(y - cy) / half_h <= 1.0


def sample(size: int, supersample: int = 3) -> list[tuple[int, int, int, int]]:
    """Render one icon at `size` px, anti-aliased by `supersample`× grid."""
    pixels: list[tuple[int, int, int, int]] = []
    radius = size * 0.22
    detail = supersample

    for py in range(size):
        for px in range(size):
            acc_r = acc_g = acc_b = acc_a = 0

            for sy in range(detail):
                for sx in range(detail):
                    x = px + (sx + 0.5) / detail
                    y = py + (sy + 0.5) / detail

                    if not coverage(x, y, size, size, radius):
                        continue

                    # Diagonal gradient across the tile.
                    t = max(0.0, min(1.0, (x + y) / (2 * size)))
                    base = lerp(GRADIENT_START, GRADIENT_END, t)

                    # Three stacked laminae, the brand mark: a filled top layer
                    # and two progressively dimmer ones below it.
                    cx, cy = size / 2, size / 2
                    layer_h = size * 0.115
                    layer_w = size * 0.255
                    alpha = 1.0
                    colour = base

                    top_cy = cy - layer_h * 1.55
                    mid_cy = cy
                    low_cy = cy + layer_h * 1.55

                    hit = False
                    if diamond(x, y, cx, top_cy, layer_w, layer_h):
                        colour = (255, 255, 255)
                        alpha = 0.97
                        hit = True
                    elif diamond(x, y, cx, mid_cy, layer_w, layer_h):
                        colour = lerp((255, 255, 255), base, 0.35)
                        alpha = 0.80
                        hit = True
                    elif diamond(x, y, cx, low_cy, layer_w, layer_h):
                        colour = lerp((255, 255, 255), base, 0.62)
                        alpha = 0.58
                        hit = True

                    if not hit:
                        # Interior fill: a very dark panel so the mark reads on
                        # both light and dark taskbars.
                        colour = lerp(BACKGROUND, base, 0.18)
                        alpha = 1.0

                    acc_r += colour[0]
                    acc_g += colour[1]
                    acc_b += colour[2]
                    acc_a += int(alpha * 255)

            total = detail * detail
            if acc_a == 0:
                pixels.append(TRANSPARENT)
            else:
                # Average only over covered samples so the edge does not darken.
                covered = acc_a / (255 * total)
                if covered <= 0:
                    pixels.append(TRANSPARENT)
                else:
                    pixels.append(
                        (
                            min(255, round(acc_r / total / covered)),
                            min(255, round(acc_g / total / covered)),
                            min(255, round(acc_b / total / covered)),
                            min(255, round(acc_a / total)),
                        )
                    )
    return pixels


def encode_png(width: int, height: int, pixels: list[tuple[int, int, int, int]]) -> bytes:
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type: none
        for x in range(width):
            raw.extend(pixels[y * width + x])

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def encode_ico(images: list[tuple[int, bytes]]) -> bytes:
    """ICO container holding PNG-compressed entries (Vista and later)."""
    header = struct.pack("<HHH", 0, 1, len(images))
    directory = b""
    payload = b""
    offset = 6 + 16 * len(images)

    for size, data in images:
        directory += struct.pack(
            "<BBBBHHII",
            size if size < 256 else 0,
            size if size < 256 else 0,
            0,
            0,
            1,
            32,
            len(data),
            offset,
        )
        payload += data
        offset += len(data)

    return header + directory + payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="assets/icons", help="output directory")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    targets = {
        "32x32.png": 32,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "icon.png": 512,
        "Square30x30Logo.png": 30,
        "Square44x44Logo.png": 44,
        "Square71x71Logo.png": 71,
        "Square89x89Logo.png": 89,
        "Square107x107Logo.png": 107,
        "Square142x142Logo.png": 142,
        "Square150x150Logo.png": 150,
        "Square284x284Logo.png": 284,
        "Square310x310Logo.png": 310,
        "StoreLogo.png": 50,
    }

    rendered: dict[int, bytes] = {}
    for name, size in targets.items():
        if size not in rendered:
            rendered[size] = encode_png(size, size, sample(size))
        (out / name).write_bytes(rendered[size])
        print(f"{name:<28} {size}×{size}  {len(rendered[size]):>7} bytes")

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    ico_entries: list[tuple[int, bytes]] = []
    for size in ico_sizes:
        if size not in rendered:
            rendered[size] = encode_png(size, size, sample(size))
        ico_entries.append((size, rendered[size]))
    (out / "icon.ico").write_bytes(encode_ico(ico_entries))
    print(f"{'icon.ico':<28} {len(ico_sizes)} sizes  {(out / 'icon.ico').stat().st_size:>7} bytes")

    print(f"\nwrote {len(targets) + 1} files to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
