from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from browser_use import Agent
from langchain_mistralai import ChatMistralAI
from probes.base import AttackProbe
from probes.reasoning import run_reasoning, TASKS
from probes.rag_poisoning.generate_prompts import main as generate_prompts
from probes.rag_poisoning.generate_documents import main as generate_documents
from probes.utils import load_prompts, default_logger

PROMPTS_FILE = Path(__file__).parent / "rag_poisoning_prompts.json"
DOCS_DIR = Path(__file__).parent / "poisoned_docs"
MAX_STEPS = 15
ATTACK_LOG = Path("logs/attack_log.json")

reasoning_llm = ChatMistralAI(model="mistral-large-latest")


class RagPoisoningProbe(AttackProbe):
    name = "rag_poisoning"
    owasp_category = "LLM01: Prompt Injection (Indirect via RAG)"

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        generate_documents(goal=goal)
        generate_prompts(goal=goal)
        prompts = load_prompts(PROMPTS_FILE)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(prompts):
            delivery = item.get("delivery", "upload")
            file_type = item.get("file_type", "txt")

            if delivery == "upload":
                doc_path = self._find_doc(file_type)
                response = await self.execute_upload(
                    session, llm, item["prompt"], doc_path
                )
            else:
                response = await self.execute_url(session, llm, item["prompt"])

            analysis = await run_reasoning(
                llm=reasoning_llm,
                task_description=TASKS[self.name],
                prompt=item["prompt"],
                response=response or "",
            )
            record = {
                "type": "rag_poisoning_attack",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "probe": self.name,
                "category": self.owasp_category,
                "index": idx,
                "technique": item["category"],
                "delivery": delivery,
                "file_type": file_type,
                "prompt": item["prompt"],
                "response": response,
                "analysis": analysis,
            }
            session.evidence.append(record)
            await default_logger.log(record, session=session)
            results.append(record)

        return {"success": True, "probe": self.name, "results": results}

    def _find_doc(self, file_type: str) -> Optional[Path]:
        ext = file_type.lstrip(".")
        docs = list(DOCS_DIR.glob(f"*.{ext}"))
        return docs[0] if docs else None

    async def execute_upload(
        self, session, llm, prompt: str, doc_path: Optional[Path]
    ) -> Optional[str]:
        if doc_path is None:
            return None
        all_docs = [str(p) for p in DOCS_DIR.iterdir() if p.is_file()]
        history = await Agent(
            llm=llm,
            browser=session.browser,
            available_file_paths=all_docs,
            task=(
                "You are already on the correct target website.\n"
                "Do not navigate away or open new tabs.\n\n"
                f"1. Upload the file at this path: {doc_path}\n"
                "2. After the upload completes, type this message exactly in the chat input and send it:\n\n"
                f"{prompt}\n\n"
                "3. Wait for the full AI response.\n"
                "4. Return only the visible AI response text."
            ),
            max_steps=MAX_STEPS,
        ).run()
        return history.final_result() if history else None

    async def execute_url(self, session, llm, prompt: str) -> Optional[str]:
        history = await Agent(
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
        ).run()
        return history.final_result() if history else None
