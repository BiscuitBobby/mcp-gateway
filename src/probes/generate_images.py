import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

# Base image shared across all probes
BASE_IMAGE = Path(__file__).parent / "man.jpg"

# Bounding box inside man.jpg where text is drawn (left, top, right, bottom)
WB = (800, 2650, 4230, 4830)


def get_font(size: int) -> ImageFont.FreeTypeFont:
    for path in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ]:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def wrap(text: str, font, max_width: int) -> List[str]:
    draw = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    lines, line = [], ""
    for word in text.split():
        test = (line + " " + word).strip()
        if draw.textlength(test, font=font) <= max_width:
            line = test
        else:
            if line:
                lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def draw_prompt(base: Image.Image, category: str, prompt: str) -> Image.Image:
    img = base.copy()
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = WB
    pad = 120
    box_w = right - left - 2 * pad
    box_h = bottom - top - 2 * pad

    # Auto-fit font size
    size = 80
    for s in range(140, 50, -5):
        font = get_font(s)
        lines = wrap(prompt, font, box_w)
        if s * 1.3 * len(lines) <= box_h * 0.78:
            size = s
            break

    font = get_font(size)
    lines = wrap(prompt, font, box_w)
    cat_font = get_font(max(50, size // 2))
    cat_lines = wrap(f"[ {category} ]", cat_font, box_w)

    total_h = (
        (len(cat_lines) * cat_font.size * 1.3)
        + (size * 0.5)
        + (len(lines) * size * 1.3)
    )
    y = top + pad + (box_h - total_h) / 2

    for line in cat_lines:
        x = left + pad + (box_w - draw.textlength(line, font=cat_font)) / 2
        draw.text((x, y), line, font=cat_font, fill=(180, 50, 50))
        y += cat_font.size * 1.3
    y += size * 0.4

    for line in lines:
        x = left + pad + (box_w - draw.textlength(line, font=font)) / 2
        draw.text((x, y), line, font=font, fill=(30, 30, 30))
        y += size * 1.3

    return img


def sanitize_name(name: str) -> str:
    name = name.lower()
    name = re.sub(r"[^\w\s-]", "", name)
    name = re.sub(r"\s+", "_", name.strip())
    return name[:60]


def generate_images(
    prompts: List[Dict[str, Any]],
    *,
    output_dir: Path | None = None,
    probe_name: str | None = None,
    framework: str | None = None,
) -> List[Dict[str, Any]]:
    """
    Generate a .png image for every prompt in *prompts*.

    Args:
        prompts:    List of prompt dicts (must have "prompt" and "category" keys).
        output_dir: Directory where images will be saved. If None, auto-constructed from probe_name and framework.
        probe_name: Name of the probe (e.g. "reconnaissance", "misinformation"). Required if output_dir is None.
        framework:  Framework name ("mitre" or "owasp"). Required if output_dir is None.

    Returns:
        The same list with "image_file" added/updated on each item.
    """
    # Auto-construct output_dir if not provided
    if output_dir is None:
        if not probe_name or not framework:
            raise ValueError(
                "Either output_dir or both probe_name and framework must be provided"
            )

        base_dir = Path(__file__).parent / framework / probe_name
        output_dir = base_dir / f"{probe_name}_images"
    if not BASE_IMAGE.exists():
        logger.warning(
            "[images] Base image not found: %s — skipping image generation", BASE_IMAGE
        )
        return prompts

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        base = Image.open(BASE_IMAGE).convert("RGB")
    except Exception:
        logger.exception("[images] Failed to open base image")
        return prompts

    for idx, item in enumerate(prompts):
        item.pop("image_file", None)
        category = item.get("category", f"prompt_{idx}")
        image_path = output_dir / f"{idx:02d}_{sanitize_name(category)}.png"

        try:
            img = draw_prompt(base, category, item["prompt"])
            img.save(str(image_path))
            item["image_file"] = str(image_path)
            logger.info("[images] Saved: %s", image_path)
        except Exception:
            logger.exception("[images] Failed for idx %d", idx)

    return prompts
