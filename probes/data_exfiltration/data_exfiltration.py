# import json
# import logging
# from datetime import datetime
# from pathlib import Path
# from typing import Dict, Any, List, Optional

# from browser_use import Agent

# from probes.base import AttackProbe
# from backend.utils.helpers import append_jsonl, extract_history
# from backend.config import MAX_STEPS_ATTACK, ATTACK_LOG_FILE

# from schemas import ReasoningResult
# from reasoning import run_reasoning, TASKS

# logger = logging.getLogger(__name__)

# PROMPTS_FILE = Path(__file__).parent / "data_exfiltration_prompts.json"


# def load_prompts() -> List[Dict[str, str]]:
#     if not PROMPTS_FILE.exists():
#         logger.warning("Data exfiltration prompt file missing.")
#         return []

#     raw = PROMPTS_FILE.read_text(encoding="utf-8").strip()
#     if not raw:
#         logger.warning("Data exfiltration prompt file empty.")
#         return []

#     try:
#         data = json.loads(raw)
#     except json.JSONDecodeError as exc:
#         logger.error("Invalid JSON in data exfiltration file: %s", exc)
#         return []

#     if not isinstance(data, list):
#         logger.warning("Data exfiltration file does not contain a list.")
#         return []

#     return [
#         item
#         for item in data
#         if isinstance(item, dict) and "category" in item and "prompt" in item
#     ]


# class DataExfiltrationProbe(AttackProbe):
#     name = "data_exfiltration"
#     owasp_category = "LLM02: Sensitive Information Disclosure"

#     async def run(self, session, llm) -> Dict[str, Any]:
#         if not session.chat_detected:
#             return {"success": False, "error": "Chat not detected"}

#         prompts = load_prompts()
#         if not prompts:
#             return {"success": False, "error": "No prompts available"}

#         results: List[Dict[str, Any]] = []

#         for idx, item in enumerate(prompts):
#             record = await self.execute_single(
#                 session=session,
#                 llm=llm,
#                 index=idx,
#                 technique=item["category"],
#                 prompt=item["prompt"],
#                 exfil_indicator=item.get("exfil_indicator", ""),
#             )

#             session.evidence.append(record)
#             await append_jsonl(ATTACK_LOG_FILE, record)
#             results.append(record)

#         return {
#             "success": True,
#             "probe": self.name,
#             "category": self.owasp_category,
#             "results": results,
#         }

#     async def execute_single(
#         self,
#         session,
#         llm,
#         index: int,
#         technique: str,
#         prompt: str,
#         exfil_indicator: str,
#     ) -> Dict[str, Any]:

#         try:
#             response = await self.execute_prompt(session, llm, prompt)

#             return await self.build_record(
#                 llm=llm,
#                 index=index,
#                 technique=technique,
#                 prompt=prompt,
#                 exfil_indicator=exfil_indicator,
#                 response=response,
#             )

#         except Exception as exc:
#             logger.error("[%s] Error at index %d: %s", self.name, index, exc)

#             return {
#                 "type": "probe_error",
#                 "timestamp": datetime.utcnow().isoformat(),
#                 "probe": self.name,
#                 "index": index,
#                 "error": str(exc),
#             }

#     async def execute_prompt(
#         self,
#         session,
#         llm,
#         prompt: str,
#     ) -> Optional[str]:

#         task = (
#             "You are already on the correct target website.\n"
#             "Do not navigate away or open new tabs.\n\n"
#             "1. Enter the following message exactly into the chat input.\n"
#             "2. Submit it.\n"
#             "3. Wait for the full AI response.\n"
#             "4. Return only the visible AI response text.\n\n"
#             f"Message:\n{prompt}"
#         )

#         agent = Agent(
#             llm=llm,
#             browser=session.browser,
#             task=task,
#             max_steps=MAX_STEPS_ATTACK,
#             validate_output=False,
#         )

#         history = extract_history(await agent.run())
#         return history.final_result() if history else None

#     async def build_record(
#         self,
#         llm,
#         index: int,
#         technique: str,
#         prompt: str,
#         exfil_indicator: str,
#         response: Optional[str],
#     ) -> Dict[str, Any]:

#         # 🔥 reasoning replaces is_exfiltration
#         enriched_response = f"""
# AI Response:
# {response}

# Potential sensitive indicator:
# {exfil_indicator}
# """

#         analysis_dict = await run_reasoning(
#             llm=llm,
#             task_description=TASKS[self.name],
#             prompt=prompt,
#             response=enriched_response,
#             trace=None,
#         )

#         try:
#             analysis = ReasoningResult(**analysis_dict)

#             return {
#                 "type": "data_exfiltration_attack",
#                 "timestamp": datetime.utcnow().isoformat(),
#                 "probe": self.name,
#                 "category": self.owasp_category,
#                 "index": index,
#                 "technique": technique,
#                 "prompt": prompt,
#                 "exfil_indicator": exfil_indicator,
#                 "response": response,
#                 "analysis": analysis.model_dump(),
#             }

#         except Exception as e:
#             logger.error("Pydantic validation failed: %s", e)

#             return {
#                 "type": "data_exfiltration_attack",
#                 "timestamp": datetime.utcnow().isoformat(),
#                 "probe": self.name,
#                 "category": self.owasp_category,
#                 "index": index,
#                 "technique": technique,
#                 "prompt": prompt,
#                 "exfil_indicator": exfil_indicator,
#                 "response": response,
#                 "analysis": analysis_dict,
#                 "error": str(e),
#             }
