import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

IMAGE_PATH = Path("man.jpg")
JSON_PATH  = Path("sensitive_information_disclosure/sensitive_info_prompts.json")
OUTPUT_DIR = Path("sensitive_information_disclosure/output_images")

WB = (800, 2650, 4230, 4830)


def get_font(size):
    for path in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ]:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def wrap(text, font, max_width):
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


def draw_prompt(base, category, prompt):
    img  = base.copy()
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = WB
    pad   = 120
    box_w = right - left - 2 * pad
    box_h = bottom - top - 2 * pad

    for size in range(140, 50, -5):
        font  = get_font(size)
        lines = wrap(prompt, font, box_w)
        if size * 1.3 * len(lines) <= box_h * 0.78:
            break

    cat_font  = get_font(max(50, size // 2))
    cat_lines = wrap(f"[ {category} ]", cat_font, box_w)
    total_h   = (len(cat_lines) * cat_font.size * 1.3) + (size * 0.5) + (len(lines) * size * 1.3)

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


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    base    = Image.open(IMAGE_PATH).convert("RGB")
    prompts = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    for i, entry in enumerate(prompts, 1):
        out = draw_prompt(base, entry["category"], entry["prompt"])
        out.save(OUTPUT_DIR / f"output_{i:03d}.png")
        print(f"[{i}/{len(prompts)}] {entry['category']}")

    print(f"\nDone. {len(prompts)} images saved to '{OUTPUT_DIR}/'")


if __name__ == "__main__":
    main()
