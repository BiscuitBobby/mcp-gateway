"""
Shared audio generator for all MITRE ATLAS probes.

Each probe calls:
    from probes.mitre.generate_audio_prompts import generate_audio
    generate_audio(prompts, probe_name="reconnaissance")

Audio files are saved to:
    src/probes/mitre/<probe_name>/<probe_name>_audio/<idx>_<category>.wav

The path is stored back into each prompt dict as "audio_file".
"""
import logging
import re
from pathlib import Path
from typing import List, Dict, Any

import numpy as np
import soundfile as sf
from kokoro import KPipeline

logger = logging.getLogger(__name__)

VOICE = "af_heart"

# Lazy-initialised so import doesn't block if kokoro isn't available
_pipeline: KPipeline | None = None


def _get_pipeline() -> KPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = KPipeline(lang_code="a")
    return _pipeline


def sanitize(name: str) -> str:
    name = name.lower()
    name = re.sub(r"[^\w\s-]", "", name)
    name = re.sub(r"\s+", "_", name.strip())
    return name[:60]  # cap length to avoid filesystem issues


def generate_audio(prompts: List[Dict[str, Any]], probe_name: str) -> List[Dict[str, Any]]:
    """
    Generate a .wav file for every prompt in *prompts*.

    Args:
        prompts:    List of prompt dicts (must have "prompt" and "category" keys).
        probe_name: Name of the MITRE probe (e.g. "reconnaissance").
                    Used to determine the output directory.

    Returns:
        The same list with "audio_file" added/updated on each item.
    """
    probe_dir = Path(__file__).parent / probe_name
    audio_dir = probe_dir / f"{probe_name}_audio"
    audio_dir.mkdir(parents=True, exist_ok=True)

    pipeline = _get_pipeline()
    sample_rate = getattr(pipeline, "sample_rate", 24000)

    for idx, item in enumerate(prompts):
        item.pop("audio_file", None)
        category = item.get("category", f"prompt_{idx}")
        audio_path = audio_dir / f"{idx:02d}_{sanitize(category)}.wav"

        try:
            chunks = [audio for _, _, audio in pipeline(item["prompt"], voice=VOICE)]
            if chunks:
                sf.write(str(audio_path), np.concatenate(chunks), sample_rate)
                item["audio_file"] = str(audio_path)
                logger.info("[mitre.audio] Saved: %s", audio_path)
            else:
                logger.warning("[mitre.audio] No audio for %s idx %d", probe_name, idx)
        except Exception:
            logger.exception("[mitre.audio] Failed for %s idx %d", probe_name, idx)

    return prompts
