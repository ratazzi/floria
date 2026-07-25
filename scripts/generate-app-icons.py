#!/usr/bin/env python3
"""Generate Floria's macOS app and menu-bar icons from one source image."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter


APP_ICON_SIZE = 1024
DOCK_ARTWORK_SCALE = 0.86


def app_icon(source: Image.Image) -> Image.Image:
    source = source.convert("RGB").resize(
        (APP_ICON_SIZE, APP_ICON_SIZE), Image.Resampling.LANCZOS
    )

    mask = Image.new("L", source.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle(
        (24, 20, 1000, 1000),
        radius=205,
        fill=255,
    )
    mask = mask.filter(ImageFilter.GaussianBlur(1.2))

    canvas = Image.new("RGBA", source.size, (0, 0, 0, 0))
    shadow_mask = Image.new("L", source.size, 0)
    shadow_mask.paste(mask, (0, 8))
    shadow_mask = shadow_mask.filter(ImageFilter.GaussianBlur(18))
    shadow_mask = shadow_mask.point(lambda alpha: round(alpha * 0.18))
    shadow = Image.new("RGBA", source.size, (24, 47, 78, 255))
    shadow.putalpha(shadow_mask)
    canvas.alpha_composite(shadow)

    clipped = source.convert("RGBA")
    clipped.putalpha(mask)
    canvas.alpha_composite(clipped)

    # macOS does not add optical padding to a custom icon. Keep the tile inside
    # the platform safe area so it has the same perceived size as system apps.
    artwork_size = round(APP_ICON_SIZE * DOCK_ARTWORK_SCALE)
    artwork = canvas.resize((artwork_size, artwork_size), Image.Resampling.LANCZOS)
    padded = Image.new("RGBA", source.size, (0, 0, 0, 0))
    offset = (APP_ICON_SIZE - artwork_size) // 2
    padded.alpha_composite(artwork, (offset, offset))
    return padded


def menu_bar_icon(source: Image.Image) -> Image.Image:
    source = source.convert("RGB")
    mask = Image.new("L", source.size, 0)

    # The source has a pale blue-white tile behind saturated blue petals. Chroma
    # isolates the mark while retaining the antialiased petal edges.
    source_pixels = source.load()
    mask_pixels = mask.load()
    for y in range(source.height):
        for x in range(source.width):
            red, green, blue = source_pixels[x, y]
            chroma = max(red, green, blue) - min(red, green, blue)
            blue_bias = max(blue, green) - red
            strength = min(chroma, blue_bias)
            mask_pixels[x, y] = max(0, min(255, (strength - 12) * 5))

    bounds = mask.getbbox()
    if bounds is None:
        raise ValueError("source image does not contain a detectable blue mark")

    mark = mask.crop(bounds)
    side = max(mark.size)
    square = Image.new("L", (side, side), 0)
    square.paste(mark, ((side - mark.width) // 2, (side - mark.height) // 2))
    square = square.resize((56, 56), Image.Resampling.LANCZOS)

    final_mask = Image.new("L", (64, 64), 0)
    final_mask.paste(square, (4, 4))
    icon = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    icon.putalpha(final_mask)
    return icon


def write_icns(icon: Image.Image, destination: Path) -> None:
    icon.save(destination, format="ICNS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()

    args.output_directory.mkdir(parents=True, exist_ok=True)
    with Image.open(args.source) as source:
        dock_icon = app_icon(source)
        status_icon = menu_bar_icon(source)

    status_icon.save(args.output_directory / "MenuBarTemplate.png")
    write_icns(dock_icon, args.output_directory / "AppIcon.icns")


if __name__ == "__main__":
    main()
