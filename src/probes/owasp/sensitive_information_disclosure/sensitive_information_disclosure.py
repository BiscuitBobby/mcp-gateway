from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS, reasoning_llm
from probes.owasp.sensitive_information_disclosure.generate_prompts import main as generate_prompts
from probes.utils import load_prompts, execute_prompt, execute_file_upload, default_logger

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
            audio_file = item.get("audio_file")
            image_file = item.get("image_file")

            if audio_file and Path(audio_file).exists():
                response = await execute_file_upload(
                    session, llm, item["prompt"], Path(audio_file), max_steps=MAX_STEPS
                )
                delivery = "audio"
            elif image_file and Path(image_file).exists():
                response = await execute_file_upload(
                    session, llm, item["prompt"], Path(image_file), max_steps=MAX_STEPS
                )
                delivery = "image"
            else:
                response = await execute_prompt(session, llm, item["prompt"], max_steps=MAX_STEPS)
                delivery = "text"

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
                "type": "sensitive_information_disclosure_attack",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "probe": self.name,
                "category": self.owasp_category,
                "index": idx,
                "technique": item["category"],
                "delivery": delivery,
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