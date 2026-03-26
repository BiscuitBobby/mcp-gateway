from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from probes.execute import run_one
from pydantic import BaseModel
import browser as browser_mod
from datetime import datetime
from typing import Optional
from enum import Enum
import asyncio
import uuid
import json

router = APIRouter(prefix="/agents")

class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


class AgentRecord:
    def __init__(self, agent_id, policies):
        self.agent_id = agent_id
        self.policies = policies
        self.status = AgentStatus.IDLE
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.created_at = datetime.utcnow().isoformat()

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "policies": self.policies,
            "cdp_url": getattr(browser_mod.instance, "cdp_url", None),
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
            result = await run_one(action)
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
        raise HTTPException(400, "Browser not ready. Call /session/start and /session/confirm first.")
    agent_id = str(uuid.uuid4())
    record = AgentRecord(
        agent_id=agent_id,
        policies=body.policies,
    )
    registry[agent_id] = record
    background_tasks.add_task(run_probes, record)
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
