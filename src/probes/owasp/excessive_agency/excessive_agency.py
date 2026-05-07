from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS, reasoning_llm
from probes.owasp.excessive_agency.generate_prompts import main as generate_prompts
from probes.utils import load_prompts, default_logger, execute_prompt

PROMPTS_FILE = Path(__file__).parent / "excessive_agency_prompts.json"
MAX_STEPS = 10


class ExcessiveAgencyProbe(AttackProbe):
    name = "excessive_agency"
    owasp_category = "LLM08: Excessive Agency"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        generate_prompts(
            app_profile=getattr(session, "app_profile", None),
            goal=goal,
            vulnerabilities=getattr(session, "vulnerabilities", None),
            interface_map=getattr(session, "interface_map", None),
        )
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
                "type": "excessive_agency_attack",
                "timestamp": datetime.now(timezone.utc).isoformat(),
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
