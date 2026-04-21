import json
import logging
import re
from pathlib import Path

import numpy as np
import soundfile as sf
from kokoro import KPipeline

logger = logging.getLogger(__name__)

AUDIO_DIR = Path(__file__).parent / "improper_output_handling_audio"
PROMPTS_FILE = Path(__file__).parent / "improper_output_handling_prompts.json"
VOICE = "af_heart"

pipeline = KPipeline(lang_code="a")


def sanitize(name: str) -> str:
    name = name.lower()
    name = re.sub(r"[^\w\s-]", "", name)
    name = re.sub(r"\s+", "_", name.strip())
    return name


def generate_audio(prompts: list) -> list:
    AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    sample_rate = getattr(pipeline, "sample_rate", 24000)

    for idx, item in enumerate(prompts):
        item.pop("audio_file", None)
        category = item.get("category", f"prompt_{idx}")
        audio_path = AUDIO_DIR / f"{idx:02d}_{sanitize(category)}.wav"

        chunks = [audio for _, _, audio in pipeline(item["prompt"], voice=VOICE)]

        if chunks:
            sf.write(str(audio_path), np.concatenate(chunks), sample_rate)
            item["audio_file"] = str(audio_path)
            logger.info("Saved: %s", audio_path)
        else:
            logger.warning("No audio for index %d (%s)", idx, category)

    return prompts


if __name__ == "__main__":
    if not PROMPTS_FILE.exists():
        raise SystemExit(f"Prompts file not found: {PROMPTS_FILE}")

    prompts = json.loads(PROMPTS_FILE.read_text(encoding="utf-8"))
    generate_audio(prompts)
    PROMPTS_FILE.write_text(json.dumps(prompts, indent=2), encoding="utf-8")

    print("Done! Audio files:")
    for item in prompts:
        print(f"  {item.get('category')} -> {item.get('audio_file', 'FAILED')}")
