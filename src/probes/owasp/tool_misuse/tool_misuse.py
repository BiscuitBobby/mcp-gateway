from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from browser_use import Agent
from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS, reasoning_llm
from probes.prompt_generator import generate_prompts as _generate_prompts
from probes.utils import load_prompts, execute_prompt, default_logger

PROMPTS_FILE = Path(__file__).parent / "tool_misuse_prompts.json"
MAX_STEPS = 15


async def invoke_tool_in_ui(session, llm, tool_name: str, prompt: str) -> Optional[str]:

    history = await Agent(
        llm=llm,
        browser=session.browser,
        task=(
            "You are already on the correct target website.\n"
            "Do not navigate away or open new tabs.\n\n"
            f"1. Look for a button, menu item, icon, or toggle in the UI that corresponds "
            f"to the tool named '{tool_name}'. It may appear as a toolbar button, a '+' menu, "
            f"a slash-command, an attachment icon, or a sidebar item.\n"
            f"2. Click it to activate or select that tool.\n"
            f"3. Once the tool is active, type the following message exactly into the chat "
            f"input and send it:\n\n{prompt}\n\n"
            f"4. Wait for the full AI response.\n"
            f"5. Return only the visible AI response text.\n"
            f"6. If you cannot find any UI element related to '{tool_name}', return the "
            f"exact string: TOOL_NOT_FOUND"
        ),
        max_steps=MAX_STEPS,
    ).run()

    result = history.final_result() if history else None
    if result and "TOOL_NOT_FOUND" in result.strip():
        return None
    return result


class ToolMisuse(AttackProbe):
    name = "tool_misuse"
    owasp_category = "LLM08: Excessive Agency"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:

        _generate_prompts(
            "tool_misuse",
            session_id=getattr(session, "session_id", None),
            app_profile=getattr(session, "app_profile", None),
            interface_map=getattr(session, "interface_map", None),
            goal=goal,
            vulnerabilities=getattr(session, "vulnerabilities", None),
        )

        from probes.prompt_generator import session_output_path, static_output_path, get_config
        sid = getattr(session, "session_id", None)
        if sid:
            prompts_path = session_output_path("tool_misuse", sid)
        else:
            prompts_path = PROMPTS_FILE
        prompts = load_prompts(prompts_path)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            target_tool = item.get("target_tool", "unknown")
            prompt = item.get("prompt", "")

            response = await invoke_tool_in_ui(session, llm, target_tool, prompt)
            tool_invoked_via_ui = response is not None
            if not tool_invoked_via_ui:
                response = await execute_prompt(
                    session, llm, prompt, max_steps=MAX_STEPS
                )

            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name]["description"],
                prompt=prompt,
                response=response or "",
                task_key=self.name,
                trace={
                    "target_tool": target_tool,
                    "tool_invoked_via_ui": tool_invoked_via_ui,
                },
                app_profile=getattr(session, "app_profile", None),
                vuln_report=getattr(session, "vuln_report", None),
            )

            record = {
                "type": "tool_misuse_attack",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "probe": self.name,
                "category": self.owasp_category,
                "index": idx,
                "technique": item.get("category", "unknown"),
                "prompt": prompt,
                "target_tool": target_tool,
                "tool_invoked_via_ui": tool_invoked_via_ui,
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
