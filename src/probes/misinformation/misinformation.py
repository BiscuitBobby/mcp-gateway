import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from browser_use import Agent
from langchain_mistralai import ChatMistralAI
from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS
from probes.misinformation.generate_prompts import main as generate_prompts

PROMPTS_FILE = Path(__file__).parent / "misinformation_prompts.json"
MAX_STEPS = 10
ATTACK_LOG = Path("logs/attack_log.jsonl")

reasoning_llm = ChatMistralAI(model="mistral-large-latest")


def load_prompts() -> List[Dict[str, str]]:
    data = json.loads(PROMPTS_FILE.read_text(encoding="utf-8"))
    return [item for item in data if "category" in item and "prompt" in item]


async def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


class MisinformationProbe(AttackProbe):
    name = "misinformation"
    owasp_category = "LLM04: Misinformation"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        generate_prompts(goal=goal)
        prompts = load_prompts()
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            response = await self.execute_prompt(session, llm, item["prompt"])
            false_claim = item.get("false_claim", "")
            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name],
                prompt=item["prompt"],
                response=response or "",
                trace={"false_claim": false_claim},
            )
            record = {
                "type": "misinformation_attack",
                "timestamp": datetime.utcnow().isoformat(),
                "probe": self.name,
                "category": self.owasp_category,
                "index": idx,
                "technique": item["category"],
                "prompt": item["prompt"],
                "false_claim": false_claim,
                "response": response,
                "analysis": analysis,
            }
            session.evidence.append(record)
            await append_jsonl(ATTACK_LOG, record)
            results.append(record)

        return {"success": True, "probe": self.name, "results": results}

    async def execute_prompt(self, session, llm, prompt: str) -> Optional[str]:
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
        )
        history = await agent.run()
        return history.final_result() if history else None