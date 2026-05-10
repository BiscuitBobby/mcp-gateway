from fastapi import (
    APIRouter,
    HTTPException,
    BackgroundTasks,
)
from fastapi.responses import StreamingResponse
from datetime import datetime, timezone
from probes.execute import run_one
from pydantic import BaseModel
import browser as browser_mod
from typing import Optional
from enum import Enum
import asyncio
import logging
import uuid
import json
import re

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents")


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
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

    def to_dict(self):
        raw_cdp = getattr(browser_mod.instance, "cdp_url", None)
        # Rewrite internal ws://localhost:PORT/... to a server-relative proxy path
        if raw_cdp:
            import re

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
            result = await run_one(action, session_id=record.session_id)
            all_results.append(result)
        record.result = json.dumps(all_results)
        record.status = AgentStatus.DONE
    except Exception as exc:
        record.error = str(exc)
        record.status = AgentStatus.ERROR


class ScanRequest(BaseModel):
    policies: list[str]


@router.get("")
async def list_agents():
    return [r.to_dict() for r in registry.values()]


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    record = registry.get(agent_id)
    if not record:
        raise HTTPException(404, "Agent not found")
    return record.to_dict()


@router.post("/scan", status_code=201)
async def scan_policies(body: ScanRequest, background_tasks: BackgroundTasks):
    if not browser_mod.ready:
        raise HTTPException(
            400, "Browser not ready. Call /session/start and /session/confirm first."
        )
    agent_id = str(uuid.uuid4())
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    record = AgentRecord(
        agent_id=agent_id, policies=body.policies, session_id=session_id
    )
    registry[agent_id] = record
    # Schedule as a real asyncio Task so it can be cancelled via /stop
    task = asyncio.ensure_future(run_probes(record))
    record.task_handle = task
    return record.to_dict()


@router.post("/{agent_id}/stop")
async def stop_agent(agent_id: str):
    record = registry.get(agent_id)
    if not record:
        raise HTTPException(404, "Agent not found")
    if record.status not in (AgentStatus.IDLE, AgentStatus.RUNNING):
        return record.to_dict()

    if record.task_handle and not record.task_handle.done():
        record.task_handle.cancel()
        try:
            await record.task_handle
        except (asyncio.CancelledError, Exception):
            pass

    record.status = AgentStatus.STOPPED
    logger.info("Agent %s stopped by request", agent_id)
    return record.to_dict()


@router.get("/{agent_id}/stream")
async def stream_agent(agent_id: str):
    if agent_id not in registry:
        raise HTTPException(404, "Agent not found")

    async def generate():
        while True:
            record = registry.get(agent_id)
            if not record:
                break
            try:
                yield f"data: {json.dumps(record.to_dict())}\n\n"
            except Exception:
                break
            if record.status in (AgentStatus.DONE, AgentStatus.ERROR):
                break
            await asyncio.sleep(1)

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.delete("/{agent_id}")
async def delete_agent(agent_id: str):
    record = registry.pop(agent_id, None)
    if not record:
        raise HTTPException(404, "Agent not found")
    return {"agent_id": agent_id, "message": "removed"}


@router.get("/cdp-url")
async def get_cdp_url():
    """Get the Chrome DevTools Protocol WebSocket URL for the current browser session."""
    cdp_url = getattr(browser_mod.instance, "cdp_url", None)
    if cdp_url:
        # Rewrite internal ws://localhost:PORT/... to a server-relative proxy path
        cdp_url = re.sub(
            r"^ws://(?:localhost|127\.0\.0\.1):(\d+)", r"/session/cdp-proxy/\1", cdp_url
        )
    return {"cdp_url": cdp_url}
