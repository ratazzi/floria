#!/usr/bin/env python3
"""Generate the checked-in background used by Floria's installer DMG."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


WIDTH = 660
HEIGHT = 420
SCALE = 2
BLUE = (20, 126, 245, 255)


def font(size: int, *, rounded: bool = False) -> ImageFont.FreeTypeFont:
    family = "SFNSRounded.ttf" if rounded else "SFNS.ttf"
    return ImageFont.truetype(f"/System/Library/Fonts/{family}", size * SCALE)


def centered_text(
    draw: ImageDraw.ImageDraw,
    y: int,
    text: str,
    text_font: ImageFont.FreeTypeFont,
    fill: tuple[int, int, int, int],
) -> None:
    bounds = draw.textbbox((0, 0), text, font=text_font)
    width = bounds[2] - bounds[0]
    draw.text(((WIDTH * SCALE - width) / 2, y * SCALE), text, font=text_font, fill=fill)


def render() -> Image.Image:
    size = (WIDTH * SCALE, HEIGHT * SCALE)
    image = Image.new("RGBA", size, (255, 255, 255, 255))
    pixels = image.load()

    for y in range(size[1]):
        progress = y / max(1, size[1] - 1)
        red = round(244 + 11 * progress)
        green = round(249 + 6 * progress)
        blue = round(255)
        for x in range(size[0]):
            distance = abs(x - size[0] / 2) / (size[0] / 2)
            glow = round(max(0.0, 1.0 - distance) * (1.0 - progress) * 3)
            pixels[x, y] = (
                min(255, red + glow),
                min(255, green + glow),
                blue,
                255,
            )

    draw = ImageDraw.Draw(image, "RGBA")
    centered_text(draw, 43, "Install Floria", font(28, rounded=True), (26, 34, 45, 255))
    centered_text(
        draw,
        82,
        "Drag Floria to Applications",
        font(15),
        (86, 96, 111, 230),
    )

    arrow_y = 226 * SCALE
    arrow_start = 278 * SCALE
    arrow_end = 382 * SCALE
    draw.line(
        (arrow_start, arrow_y, arrow_end, arrow_y),
        fill=(*BLUE[:3], 150),
        width=3 * SCALE,
    )
    draw.line(
        (arrow_end - 15 * SCALE, arrow_y - 12 * SCALE, arrow_end, arrow_y),
        fill=(*BLUE[:3], 150),
        width=3 * SCALE,
    )
    draw.line(
        (arrow_end - 15 * SCALE, arrow_y + 12 * SCALE, arrow_end, arrow_y),
        fill=(*BLUE[:3], 150),
        width=3 * SCALE,
    )

    centered_text(
        draw,
        378,
        "Your encrypted Library stays on this Mac.",
        font(12),
        (109, 118, 131, 185),
    )
    return image.resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS).convert("RGB")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    render().save(args.destination, optimize=True)


if __name__ == "__main__":
    main()
