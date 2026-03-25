from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import browser as browser_mod
from browser_use import Agent
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
    def __init__(self, agent_id, task, agent):
        self.agent_id = agent_id
        self.task = task
        self.agent = agent
        self.status = AgentStatus.IDLE
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.created_at = datetime.utcnow().isoformat()

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "task": self.task,
            "cdp_url": getattr(browser_mod.instance, "cdp_url", None),
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
        }


registry: dict[str, AgentRecord] = {}


async def run_agent(record: AgentRecord):
    record.status = AgentStatus.RUNNING
    try:
        result = await record.agent.run()
        record.result = str(result)
        record.status = AgentStatus.DONE
    except Exception as exc:
        record.error = str(exc)
        record.status = AgentStatus.ERROR


class CreateAgentRequest(BaseModel):
    task: str
    autorun: bool = True


class InteractRequest(BaseModel):
    message: str


@router.get("")
async def list_agents():
    return [r.to_dict() for r in registry.values()]


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    record = registry.get(agent_id)
    if not record:
        raise HTTPException(404, "Agent not found")
    return record.to_dict()


@router.post("", status_code=201)
async def create_agent(body: CreateAgentRequest, background_tasks: BackgroundTasks):
    if not browser_mod.ready:
        raise HTTPException(400, "Browser not ready. Call /session/start and /session/confirm first.")
    agent_id = str(uuid.uuid4())
    record = AgentRecord(
        agent_id=agent_id,
        task=body.task,
        agent=Agent(llm=browser_mod.llm, task=body.task, browser_session=browser_mod.instance),
    )
    registry[agent_id] = record
    if body.autorun:
        background_tasks.add_task(run_agent, record)
    return record.to_dict()


@router.post("/{agent_id}/interact")
async def interact_with_agent(agent_id: str, body: InteractRequest, background_tasks: BackgroundTasks):
    record = registry.get(agent_id)
    if not record:
        raise HTTPException(404, "Agent not found")
    if record.status == AgentStatus.RUNNING:
        raise HTTPException(409, "Agent is busy")
    record.agent = Agent(llm=browser_mod.llm, task=body.message, browser_session=browser_mod.instance)
    record.task = body.message
    record.result = None
    record.error = None
    background_tasks.add_task(run_agent, record)
    return {"agent_id": agent_id, "task": body.message, "cdp_url": getattr(browser_mod.instance, "cdp_url", None)}


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
