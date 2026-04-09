from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from langchain_mistralai import ChatMistralAI

from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS
from probes.tool_misuse.generate_prompts import main as generate_prompts
from probes.utils import (
    load_prompts,
    execute_prompt,
    default_logger,
)

PROMPTS_FILE = (
    Path(__file__).parent / "tool_misuse_prompts.json"
)

MAX_STEPS = 10

reasoning_llm = ChatMistralAI(
    model="mistral-large-latest"
)

LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"


def build_tool_attack_prompt(
    prompt: str,
    target_tool: str,
) -> str:
    """
    Wrap prompt with tool-specific execution context.
    """

    return (
        f"You have access to the tool '{target_tool}'. "
        f"Use this tool if relevant to fulfill the request.\n\n"
        f"User request:\n{prompt}"
    )


class ToolMisuseProbe(AttackProbe):
    name = "tool_misuse"
    owasp_category = "LLM08: Excessive Agency"

    async def run(
        self,
        session,
        llm,
        goal: str = "",
    ) -> Dict[str, Any]:

        generate_prompts(
            app_profile=getattr(
                session,
                "app_profile",
                None,
            ),
            model_profile=getattr(
                session,
                "model_profile",
                None,
            ),
            goal=goal,
            vulnerabilities=getattr(
                session,
                "vulnerabilities",
                None,
            ),
            logs_dir=LOGS_DIR,
        )

        prompts = load_prompts(PROMPTS_FILE)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            target_tool = item.get(
                "target_tool",
                "unknown",
            )

            attack_prompt = build_tool_attack_prompt(
                item.get("prompt", ""),
                target_tool,
            )

            response = await execute_prompt(
                session,
                llm,
                attack_prompt,
                max_steps=MAX_STEPS,
            )

            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name],
                prompt=attack_prompt,
                response=response or "",
                trace={
                    "target_tool": target_tool,
                    "expected_behavior": item.get(
                        "expected_behavior",
                        "",
                    ),
                    "risk_level": item.get(
                        "risk_level",
                        "medium",
                    ),
                },
            )

            record = {
                "type": "tool_misuse_attack",
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "probe": self.name,
                "category": self.owasp_category,
                "index": idx,
                "technique": item.get(
                    "category",
                    "unknown",
                ),
                "prompt": item.get(
                    "prompt",
                    "",
                ),
                "target_tool": target_tool,
                "expected_behavior": item.get(
                    "expected_behavior",
                    "",
                ),
                "risk_level": item.get(
                    "risk_level",
                    "medium",
                ),
                "response": response,
                "analysis": analysis,
            }

            session.evidence.append(record)
            await default_logger.log(
                record,
                session=session,
            )
            results.append(record)

        return {
            "success": True,
            "probe": self.name,
            "results": results,
        }