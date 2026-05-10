import re
import wave
import json
import logging
import asyncio
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from browser_use import Agent

logger = logging.getLogger(__name__)


def load_prompts(prompts_file: Path) -> List[Dict[str, Any]]:
    """Load prompts from a JSON file, ensuring they have required fields."""
    if not prompts_file.exists():
        logger.error(f"Prompts file not found: {prompts_file}")
        return []
    try:
        data = json.loads(prompts_file.read_text(encoding="utf-8"))
        return [item for item in data if "category" in item and "prompt" in item]
    except Exception as e:
        logger.error(f"Error loading prompts from {prompts_file}: {e}")
        return []


def _build_payload_file(payload_spec: dict) -> Optional[Path]:
    """
    Construct a temporary file from payload_spec.
    Expects at minimum: file_type, and one of: content, hidden_content, spoken_instruction.
    Returns the path to the temp file, or None if construction fails.
    """
    try:
        file_type = payload_spec.get("file_type", "txt").lstrip(".").lower()
        content = (
            payload_spec.get("content")
            or payload_spec.get("hidden_content")
            or payload_spec.get("visible_content")
            or payload_spec.get("spoken_instruction")
            or json.dumps(payload_spec)
        )
        suffix = f".{file_type}"
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix=suffix, mode="w", encoding="utf-8"
        )
        tmp.write(content)
        tmp.flush()
        return Path(tmp.name)
    except Exception as e:
        logger.error(f"Failed to build payload file: {e}")
        return None


async def execute_prompt(
    session, llm, prompt: str, max_steps: int = 10
) -> Optional[str]:
    """Execute a single prompt using the browser-use Agent."""
    agent = Agent(
        llm=llm,
        browser=session.browser,
        task=(
            "You are already on the correct target website.\n"
            "Do not navigate away or open new tabs.\n\n"
            "1. Enter the following message exactly into the chat input.\n"
            "2. Submit it.\n"
            "3. Wait for the full AI response.\n"
            "4. Return only the visible AI response text.\n\n"
            f"Message:\n{prompt}"
        ),
        max_steps=max_steps,
    )
    history = await agent.run()
    return history.final_result() if history else None


async def execute_file_upload(
    session, llm, prompt: str, file_path: Path, max_steps: int = 15
) -> Optional[str]:
    """Upload a pre-existing file (audio, image, doc) then send the text prompt."""
    agent = Agent(
        llm=llm,
        browser=session.browser,
        available_file_paths=[str(file_path)],
        task=(
            "You are already on the correct target website.\n"
            "Do not navigate away or open new tabs.\n\n"
            f"1. Upload the file at this path: {file_path}\n"
            "2. After the upload completes, type this message exactly into the chat input and send it:\n\n"
            f"{prompt}\n\n"
            "3. Wait for the full AI response.\n"
            "4. Return only the visible AI response text."
        ),
        max_steps=max_steps,
    )
    history = await agent.run()
    return history.final_result() if history else None


async def execute_prompt_with_file(
    session, llm, prompt: str, payload_spec: dict, max_steps: int = 10
) -> Optional[str]:
    """Execute a prompt that requires uploading a file payload first."""
    file_path = _build_payload_file(payload_spec)
    if file_path is None:
        logger.warning("payload file construction failed, falling back to text-only")
        return await execute_prompt(session, llm, prompt, max_steps)

    agent = Agent(
        llm=llm,
        browser=session.browser,
        task=(
            "You are already on the correct target website.\n"
            "Do not navigate away or open new tabs.\n\n"
            f"1. Upload the file at this path: {file_path}\n"
            "2. Enter the following message exactly into the chat input.\n"
            "3. Submit it.\n"
            "4. Wait for the full AI response.\n"
            "5. Return only the visible AI response text.\n\n"
            f"Message:\n{prompt}"
        ),
        max_steps=max_steps,
    )
    history = await agent.run()

    try:
        file_path.unlink()
    except Exception:
        pass

    return history.final_result() if history else None


class AttackLogger:
    """Centralized logger for attack probe results with deduplication."""

    _lock = asyncio.Lock()
    _seen_hashes = set()

    def __init__(self, path: Path = Path("logs/attack_log.json")):
        self.path = path

    def _get_hash(self, record: dict) -> str:
        """Generate a hash for deduplication based on probe, technique, prompt, and response."""
        content = f"{record.get('probe')}|{record.get('technique')}|{record.get('prompt')}|{record.get('response')}"
        return str(hash(content))

    async def log(
        self, record: dict, session: Optional[Any] = None, deduplicate: bool = True
    ) -> None:
        """Centralized JSONL logging with optional session context and deduplication."""
        if session:
            record["session_id"] = getattr(session, "session_id", "N/A")
            record["target_name"] = getattr(session, "target_name", "N/A")
            record["target_url"] = getattr(session, "target_url", "N/A")

            self.path = Path(f"logs/attack_log_{session.session_id}.json")

        if deduplicate:
            record_hash = self._get_hash(record)
            async with self._lock:
                if record_hash in self._seen_hashes:
                    logger.debug(
                        f"Skipping duplicate log entry for {record.get('probe')}"
                    )
                    return
                self._seen_hashes.add(record_hash)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        async with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")


def get_probe_totals() -> Dict[str, int]:
    """
    Dynamically calculate the total number of probes for each OWASP category
    based on the registered probes and their prompt files.
    """
    from probes.registry import get_owasp_probes, get_mitre_probes

    # Map from probe action name to OWASP short code (matching dashboard.html)
    owasp_map = {
        "prompt_injection": "LLM01",
        "sensitive_information_disclosure": "LLM02",
        "improper_output_handling": "LLM05",
        "misinformation": "LLM04",
        "data_exfiltration": "LLM06",
        "excessive_agency": "LLM08",
        "tool_misuse": "LLM08",
        "rag_poisoning": "LLM09",
    }

    mitre_map = {
        "attack_staging": "Attack Staging",
        "collection": "Collection",
        "context_manipulation": "Context Manipulation",
        "credential_extraction": "Credential Extraction",
        "discovery": "Discovery",
        "evasion_techniques": "Evasion Techniques",
        "impact": "Impact",
        "lateral_movement": "Lateral Movement",
        "reconnaissance": "Reconnaissance",
        "user_execution": "User Execution",
    }

    totals = {}
    base_path = Path(__file__).parent

    # Count OWASP probes
    for key, info in get_owasp_probes().items():
        cat = owasp_map.get(key)
        if not cat:
            continue
        filename = info.get("prompts_file")
        if not filename:
            continue
        prompts_path = base_path / "owasp" / key / filename
        count = 0
        if prompts_path.exists():
            try:
                data = json.loads(prompts_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    count = len(data)
            except Exception:
                pass
        totals[cat] = totals.get(cat, 0) + count

    # Count MITRE probes
    for key, info in get_mitre_probes().items():
        cat = mitre_map.get(key)
        if not cat:
            continue
        # MITRE probes may not have prompts_file in registry, use config
        from probes.probe_configs import MITRE_PROBES

        config = MITRE_PROBES.get(key, {})
        dir_name = config.get("dir_name", key)
        filename = config.get("output_file", "")
        if not filename:
            continue
        prompts_path = base_path / "mitre" / dir_name / filename
        count = 0
        if prompts_path.exists():
            try:
                data = json.loads(prompts_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    count = len(data)
            except Exception:
                pass
        totals[cat] = totals.get(cat, 0) + count

    return totals


default_logger = AttackLogger()


# ============================================================================
# Audio Generation Utilities
# ============================================================================

try:
    from piper import PiperVoice
except ImportError:
    logger.error("piper-tts not installed. Audio generation will be disabled.")
    PiperVoice = None


def sanitize(name: str) -> str:
    """
    Sanitize a string for use in filenames.

    Args:
        name: The string to sanitize

    Returns:
        A filesystem-safe string (lowercase, alphanumeric + underscores/hyphens)
    """
    name = name.lower()
    name = re.sub(r"[^\w\s-]", "", name)
    name = re.sub(r"\s+", "_", name.strip())
    return name[:60]


def generate_audio(
    prompts: List[Dict[str, Any]], output_dir: Path, voice: str = "danny"
) -> List[Dict[str, Any]]:
    """
    Generate a .wav file for every prompt in the list.

    Args:
        prompts: List of prompt dicts (must have "prompt" and optionally "category" keys).
        output_dir: Directory where audio files will be saved.
        voice: Voice model name or path to .onnx model file (default: "danny").
               If just a name is provided, looks for model in src/models/<voice>/en_US-<voice>-low.onnx

    Returns:
        The same list with "audio_file" added/updated on each item.
    """
    if PiperVoice is None:
        logger.warning(
            "[audio_generator] PiperVoice not available. Skipping audio generation."
        )
        return prompts

    output_dir.mkdir(parents=True, exist_ok=True)

    # Resolve model path
    if voice.endswith(".onnx"):
        model_path = voice
    else:
        # Go up from probes/ to src/ then to models/
        models_dir = Path(__file__).parent.parent / "models" / voice
        model_path = str(models_dir / f"en_US-{voice}-low.onnx")

    # Load voice model
    try:
        piper_voice = PiperVoice.load(model_path)
    except Exception:
        logger.exception("[audio_generator] Failed to load voice model: %s", model_path)
        return prompts

    # Generate audio for each prompt
    for idx, item in enumerate(prompts):
        item.pop("audio_file", None)

        category = item.get("category", f"prompt_{idx}")
        audio_path = output_dir / f"{idx:02d}_{sanitize(category)}.wav"

        try:
            with wave.open(str(audio_path), "wb") as wav_file:
                piper_voice.synthesize_wav(item["prompt"], wav_file)

            item["audio_file"] = str(audio_path)
            logger.info("[audio_generator] Saved: %s", audio_path)
        except Exception:
            logger.exception(
                "[audio_generator] Failed to generate audio for index %d (%s)",
                idx,
                category,
            )

    return prompts
