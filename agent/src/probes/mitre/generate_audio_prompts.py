"""
MITRE ATLAS audio generator wrapper.

Each probe calls:
    from probes.mitre.generate_audio_prompts import generate_audio
    generate_audio(prompts, probe_name="reconnaissance")

Audio files are saved to:
    src/probes/mitre/<probe_name>/<probe_name>_audio/<idx>_<category>.wav

The path is stored back into each prompt dict as "audio_file".
"""

from pathlib import Path
from typing import List, Dict, Any

from probes.utils import generate_audio as _generate_audio


def generate_audio(
    prompts: List[Dict[str, Any]], probe_name: str
) -> List[Dict[str, Any]]:
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

    return _generate_audio(prompts=prompts, output_dir=audio_dir, voice="danny")
