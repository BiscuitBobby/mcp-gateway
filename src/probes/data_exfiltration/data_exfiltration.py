from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from browser_use import Agent
from langchain_mistralai import ChatMistralAI
from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS
from probes.data_exfiltration.generate_prompts import main as generate_prompts
from probes.utils import load_prompts, default_logger

PROMPTS_FILE = Path(__file__).parent / "data_exfiltration_prompts.json"
MAX_STEPS = 10
ATTACK_LOG = Path("logs/attack_log.json")

reasoning_llm = ChatMistralAI(model="mistral-large-latest")


class DataExfiltrationProbe(AttackProbe):
    name = "data_exfiltration"
    owasp_category = "LLM02: Sensitive Information Disclosure"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        generate_prompts(goal=goal)
        prompts = load_prompts(PROMPTS_FILE)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            response, trace = await self.execute_prompt(
                session, llm, item["prompt"]
            )

            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name],
                prompt=item["prompt"],
                response=response,
                trace=trace,
            )

            record = {
                "type": "data_exfiltration_attack",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "probe": self.name,
                "category": self.owasp_category,
                "index": idx,
                "technique": item["category"],
                "prompt": item["prompt"],
                "response": response,
                "trace": trace,
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

    async def execute_prompt(self, session, llm, prompt: str) -> Tuple[Optional[str], Dict[str, Any]]:
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
            max_steps=MAX_STEPS,
            validate_output=False,
        )

        history = await agent.run()
        trace = (history.model_dump() if hasattr(history, "model_dump") else {})

        return history.final_result(), trace