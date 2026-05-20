from datetime import datetime
from typing import Optional
from enum import Enum
from pydantic import BaseModel
import browser as browser_mod
from probes.execute import run_one
import asyncio
import json
import re


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    DONE = "done"
    ERROR = "error"
    STOPPED = "stopped"


class AgentRecord:
    def __init__(self, agent_id, policies, session_id: Optional[str] = None):
        self.agent_id = agent_id
        self.policies = policies
        self.session_id = session_id
        self.status = AgentStatus.IDLE
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.created_at = datetime.utcnow().isoformat()
        # asyncio.Task handle — set after the task is scheduled so it can be cancelled
        self.task_handle: Optional[asyncio.Task] = None
        # Event used to pause/resume execution between probes
        self.resume_event: asyncio.Event = asyncio.Event()
        self.resume_event.set()  # not paused by default

    def to_dict(self):
        raw_cdp = getattr(browser_mod.instance, "cdp_url", None)
        # Rewrite internal ws://localhost:PORT/... to a server-relative proxy path
        if raw_cdp:
            raw_cdp = re.sub(
                r"^ws://(?:localhost|127\.0\.0\.1):(\d+)",
                r"/session/cdp-proxy/\1",
                raw_cdp,
            )
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "policies": self.policies,
            "cdp_url": raw_cdp,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
        }


registry: dict[str, AgentRecord] = {}


async def run_probes(record: AgentRecord):
    record.status = AgentStatus.RUNNING
    all_results = []
    try:
        for action in record.policies:
            # Wait here if paused (between probes)
            await record.resume_event.wait()
            # Re-check after resuming in case the task was stopped while paused
            if record.status == AgentStatus.STOPPED:
                break
            result = await run_one(action, session_id=record.session_id)
            all_results.append(result)
        if record.status != AgentStatus.STOPPED:
            record.result = json.dumps(all_results)
            record.status = AgentStatus.DONE
    except Exception as exc:
        record.error = str(exc)
        record.status = AgentStatus.ERROR


class ScanRequest(BaseModel):
    policies: list[str]
    send_audio: bool = False
    send_images: bool = False


class DeliveryOptions(BaseModel):
    send_audio: bool
    send_images: bool
