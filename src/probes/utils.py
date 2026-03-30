import json
import logging
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
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

async def execute_prompt(session, llm, prompt: str, max_steps: int = 10) -> Optional[str]:
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

    async def log(self, record: dict, session: Optional[Any] = None, deduplicate: bool = True) -> None:
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
                    logger.debug(f"Skipping duplicate log entry for {record.get('probe')}")
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
    from probes.registry import get_probes
    probes = get_probes()
    
    # Map from probe action name to OWASP short code (matching dashboard.html)
    owasp_map = {
        "prompt_injection": "LLM01",
        "sensitive_information_disclosure": "LLM02",
        "improper_output_handling": "LLM02",
        "data_exfiltration": "LLM06",
        "excessive_agency": "LLM08",
        "rag_poisoning": "LLM09",
        "misinformation": "LLM04",
        "tool_abuse": "LLM07",
    }
    
    totals = {}
    base_path = Path(__file__).parent
    
    for key, info in probes.items():
        cat = owasp_map.get(key)
        if not cat:
            continue
            
        filename = info.get("prompts_file")
        if not filename:
            continue
            
        # The prompts file is relative to the probe's directory
        prompts_path = base_path / key / filename
        
        count = 0
        if prompts_path.exists():
            try:
                data = json.loads(prompts_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    count = len(data)
            except Exception:
                # If file exists but is invalid JSON or not a list, count is 0
                pass
        
        totals[cat] = totals.get(cat, 0) + count
        
    return totals
        

default_logger = AttackLogger()
