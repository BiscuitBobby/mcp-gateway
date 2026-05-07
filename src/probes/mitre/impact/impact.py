from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS, reasoning_llm
from probes.mitre.impact.generate_prompts import main as generate_prompts
from probes.utils import load_prompts, execute_prompt, default_logger

PROMPTS_FILE = Path(__file__).parent / "impact_prompts.json"
MAX_STEPS = 10


class Impact(AttackProbe):
    name = "impact"
    mitre_category = "Impact"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        prompts = generate_prompts(
            goal=goal,
            app_profile=getattr(session, "app_profile", None),
            interface_map=getattr(session, "interface_map", None),
            vulnerabilities=getattr(session, "vuln_report", None),
        )
        if not prompts:
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
                "type": "impact_attack",
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
