#!/usr/bin/env python3
"""Generate the checked-in background used by Floria's installer DMG."""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


WIDTH = 660
HEIGHT = 420
SUPERSAMPLE = 2
BLUE = (20, 126, 245, 255)


def font(size: int, scale: int, *, rounded: bool = False) -> ImageFont.FreeTypeFont:
    family = "SFNSRounded.ttf" if rounded else "SFNS.ttf"
    return ImageFont.truetype(f"/System/Library/Fonts/{family}", size * scale)


def centered_text(
    draw: ImageDraw.ImageDraw,
    y: int,
    text: str,
    text_font: ImageFont.FreeTypeFont,
    fill: tuple[int, int, int, int],
    scale: int,
) -> None:
    bounds = draw.textbbox((0, 0), text, font=text_font)
    width = bounds[2] - bounds[0]
    draw.text(((WIDTH * scale - width) / 2, y * scale), text, font=text_font, fill=fill)


def render(representation_scale: int) -> Image.Image:
    scale = representation_scale * SUPERSAMPLE
    size = (WIDTH * scale, HEIGHT * scale)
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
    centered_text(
        draw,
        43,
        "Install Floria",
        font(28, scale, rounded=True),
        (26, 34, 45, 255),
        scale,
    )
    centered_text(
        draw,
        82,
        "Drag Floria to Applications",
        font(15, scale),
        (86, 96, 111, 230),
        scale,
    )

    arrow_y = 226 * scale
    arrow_start = 278 * scale
    arrow_end = 382 * scale
    draw.line(
        (arrow_start, arrow_y, arrow_end, arrow_y),
        fill=(*BLUE[:3], 150),
        width=3 * scale,
    )
    draw.line(
        (arrow_end - 15 * scale, arrow_y - 12 * scale, arrow_end, arrow_y),
        fill=(*BLUE[:3], 150),
        width=3 * scale,
    )
    draw.line(
        (arrow_end - 15 * scale, arrow_y + 12 * scale, arrow_end, arrow_y),
        fill=(*BLUE[:3], 150),
        width=3 * scale,
    )

    centered_text(
        draw,
        378,
        "Your encrypted Library stays on this Mac.",
        font(12, scale),
        (109, 118, 131, 185),
        scale,
    )
    return image.resize(
        (WIDTH * representation_scale, HEIGHT * representation_scale),
        Image.Resampling.LANCZOS,
    ).convert("RGB")


def save_retina_tiff(destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="floria-dmg-background.") as directory:
        directory_path = Path(directory)
        standard = directory_path / "DmgBackground.tiff"
        retina = directory_path / "DmgBackground@2x.tiff"
        render(1).save(standard, compression="tiff_lzw", dpi=(72, 72))
        render(2).save(retina, compression="tiff_lzw", dpi=(144, 144))
        subprocess.run(
            [
                "/usr/bin/tiffutil",
                "-cathidpicheck",
                str(standard),
                str(retina),
                "-out",
                str(destination),
            ],
            check=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    save_retina_tiff(args.destination)


if __name__ == "__main__":
    main()
