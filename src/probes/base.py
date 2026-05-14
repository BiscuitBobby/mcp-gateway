from datetime import datetime, timezone
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from pathlib import Path

from probes.reasoning import run_reasoning, TASKS, reasoning_llm
from probes.utils import (
    load_prompts,
    execute_prompt,
    execute_file_upload,
    default_logger,
)

# Runtime delivery flags — checked per-prompt so toggling mid-run takes effect immediately
send_audio: bool = False
send_images: bool = False


def set_delivery_options(audio: bool, images: bool) -> None:
    global send_audio, send_images
    send_audio = audio
    send_images = images


class AttackProbe(ABC):
    name: str = "base_probe"
    owasp_category: str = "unknown"
    mitre_category: str = "unknown"

    @abstractmethod
    async def run(self, session, llm, goal: str = "") -> dict[str, Any]:
        pass


class StandardProbe(AttackProbe):
    """
    Probe with the standard generate → execute → reason loop.

    Subclasses only need to set class attributes:
        name, record_type, prompts_file,
        and either owasp_category or mitre_category.
    """

    record_type: str = "attack"
    prompts_file: Path = Path("prompts.json")
    max_steps: int = 10

    async def run(self, session, llm, goal: str = "") -> Dict[str, Any]:
        from probes.prompt_generator import generate_prompts

        prompts = generate_prompts(
            self.name,
            goal=goal,
            app_profile=getattr(session, "app_profile", None),
            interface_map=getattr(session, "interface_map", None),
            vulnerabilities=getattr(session, "vuln_report", None),
        )
        if not prompts:
            prompts = load_prompts(self.prompts_file)

        results: List[Dict[str, Any]] = []
        category_field = (
            self.owasp_category
            if self.owasp_category != "unknown"
            else self.mitre_category
        )

        for idx, item in enumerate(prompts):
            deliveries: list[tuple[str, Any]] = []

            # Text is always sent
            text_response = await execute_prompt(
                session, llm, item["prompt"], max_steps=self.max_steps
            )
            deliveries.append(("text", text_response))

            # Audio — sent if enabled and file exists
            audio_file = item.get("audio_file")
            if send_audio and audio_file and Path(audio_file).exists():
                audio_response = await execute_file_upload(
                    session, llm, item["prompt"], Path(audio_file), max_steps=self.max_steps
                )
                deliveries.append(("audio", audio_response))

            # Image — sent if enabled and file exists
            image_file = item.get("image_file")
            if send_images and image_file and Path(image_file).exists():
                image_response = await execute_file_upload(
                    session, llm, item["prompt"], Path(image_file), max_steps=self.max_steps
                )
                deliveries.append(("image", image_response))

            for delivery, response in deliveries:
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
                    "type": self.record_type,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "probe": self.name,
                    "category": category_field,
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
