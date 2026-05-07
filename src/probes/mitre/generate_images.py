"""
Shared image generator for all MITRE ATLAS probes.

Each probe calls:
    from probes.mitre.generate_images import generate_images
    generate_images(prompts, probe_name="reconnaissance")

Images are saved to:
    src/probes/mitre/<probe_name>/<probe_name>_images/<idx>_<category>.png

The path is stored back into each prompt dict as "image_file".

The image overlays the prompt text onto the base image (man.jpg) located at
src/probes/man.jpg — the same base used by the OWASP image generators.
"""
import logging
import re
from pathlib import Path
from typing import List, Dict, Any

from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

# Base image shared with OWASP probes
BASE_IMAGE = Path(__file__).parent.parent / "man.jpg"

# Bounding box inside man.jpg where text is drawn (left, top, right, bottom)
WB = (800, 2650, 4230, 4830)


def _get_font(size: int) -> ImageFont.FreeTypeFont:
    for path in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ]:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap(text: str, font, max_width: int) -> List[str]:
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


def _draw_prompt(base: Image.Image, category: str, prompt: str) -> Image.Image:
    img = base.copy()
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = WB
    pad = 120
    box_w = right - left - 2 * pad
    box_h = bottom - top - 2 * pad

    # Auto-fit font size
    size = 80
    for s in range(140, 50, -5):
        font = _get_font(s)
        lines = _wrap(prompt, font, box_w)
        if s * 1.3 * len(lines) <= box_h * 0.78:
            size = s
            break

    font = _get_font(size)
    lines = _wrap(prompt, font, box_w)
    cat_font = _get_font(max(50, size // 2))
    cat_lines = _wrap(f"[ {category} ]", cat_font, box_w)

    total_h = (len(cat_lines) * cat_font.size * 1.3) + (size * 0.5) + (len(lines) * size * 1.3)
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


def sanitize(name: str) -> str:
    name = name.lower()
    name = re.sub(r"[^\w\s-]", "", name)
    name = re.sub(r"\s+", "_", name.strip())
    return name[:60]


def generate_images(prompts: List[Dict[str, Any]], probe_name: str) -> List[Dict[str, Any]]:
    """
    Generate a .png image for every prompt in *prompts*.

    Args:
        prompts:    List of prompt dicts (must have "prompt" and "category" keys).
        probe_name: Name of the MITRE probe (e.g. "reconnaissance").

    Returns:
        The same list with "image_file" added/updated on each item.
    """
    if not BASE_IMAGE.exists():
        logger.warning("[mitre.images] Base image not found: %s — skipping image generation", BASE_IMAGE)
        return prompts

    probe_dir = Path(__file__).parent / probe_name
    image_dir = probe_dir / f"{probe_name}_images"
    image_dir.mkdir(parents=True, exist_ok=True)

    try:
        base = Image.open(BASE_IMAGE).convert("RGB")
    except Exception:
        logger.exception("[mitre.images] Failed to open base image")
        return prompts

    for idx, item in enumerate(prompts):
        item.pop("image_file", None)
        category = item.get("category", f"prompt_{idx}")
        image_path = image_dir / f"{idx:02d}_{sanitize(category)}.png"

        try:
            img = _draw_prompt(base, category, item["prompt"])
            img.save(str(image_path))
            item["image_file"] = str(image_path)
            logger.info("[mitre.images] Saved: %s", image_path)
        except Exception:
            logger.exception("[mitre.images] Failed for %s idx %d", probe_name, idx)

    return prompts
