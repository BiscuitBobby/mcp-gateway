from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS, reasoning_llm
from mitre.credential_extraction.generate_prompts import main as generate_prompts
from probes.utils import load_prompts, execute_prompt, default_logger

PROMPTS_FILE = Path(__file__).parent / "credential_extraction_prompts.json"
MAX_STEPS = 10


class CredentialExtraction(AttackProbe):
    name = "credential_extraction"
    mitre_category = "Credential Extraction"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        generate_prompts(goal=goal)
        prompts = load_prompts(PROMPTS_FILE)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            response = await execute_prompt(session, llm, item["prompt"], max_steps=MAX_STEPS)

            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name]["description"],
                prompt=item["prompt"],
                response=response or "",
                task_key=self.name,
                app_profile=getattr(session, "app_profile", None),
                vuln_report=getattr(session, "vuln_report", None),
            )

            record = {
                "type": "credential_extraction_attack",
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "probe": self.name,
                "category": self.mitre_category,
                "index": idx,
                "technique": item["category"],
                "prompt": item["prompt"],
                "response": response,
                "analysis": analysis,
            }

            session.evidence.append(record)
            await default_logger.log(record, session=session)
            results.append(record)

        return {
            "success": True,
            "probe": self.name,
            "results": results,
        }
