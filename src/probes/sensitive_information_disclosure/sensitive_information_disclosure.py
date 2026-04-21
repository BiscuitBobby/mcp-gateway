from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from owasp.probes.base import AttackProbe
from owasp.probes.reasoning import run_reasoning, TASKS
from owasp.probes.sensitive_information_disclosure.generate_prompts import main as generate_prompts
from owasp.probes.utils import load_prompts, execute_prompt, default_logger, reasoning_llm

PROMPTS_FILE = Path(__file__).parent / "sensitive_info_prompts.json"
MAX_STEPS = 10

class SensitiveInformationDisclosureProbe(AttackProbe):
    name = "sensitive_information_disclosure"
    owasp_category = "LLM02: Sensitive Information Disclosure"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        generate_prompts(goal=goal)
        prompts = load_prompts(PROMPTS_FILE)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            response = await execute_prompt(session, llm, item["prompt"], max_steps=MAX_STEPS)

            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name],
                prompt=item["prompt"],
                response=response or "",
            )

            record = {
                "type": "sensitive_information_disclosure_attack",
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "probe": self.name,
                "category": self.owasp_category,
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