from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from langchain_mistralai import ChatMistralAI
from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS
from probes.prompt_injection.generate_prompts import main as generate_prompts
from probes.utils import load_prompts, execute_prompt, default_logger

PROMPTS_FILE = Path(__file__).parent / "prompt_injection_prompts.json"
MAX_STEPS = 10
ATTACK_LOG = Path("logs/attack_log.json")

reasoning_llm = ChatMistralAI(model="mistral-large-latest")


class PromptInjectionProbe(AttackProbe):
    name = "prompt_injection"
    owasp_category = "LLM01: Prompt Injection"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        generate_prompts(goal=goal)
        prompts = load_prompts(PROMPTS_FILE)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            response = await execute_prompt(
                session, llm, item["prompt"], max_steps=MAX_STEPS
            )
            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name],
                prompt=item["prompt"],
                response=response or "",
            )
            record = {
                "type": "prompt_injection_attack",
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

        return {"success": True, "probe": self.name, "results": results}
