from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from probes.execute import run_one_mitre
from probes.registry import get_mitre_probes
from pydantic import BaseModel
import browser as browser_mod
from datetime import datetime, timezone
from typing import Optional
from enum import Enum
import asyncio
import uuid
import json
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mitre")


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    STOPPED = "stopped"


class MitreScanRecord:
    def __init__(
        self, scan_id: str, policies: list[str], session_id: Optional[str] = None
    ):
        self.scan_id = scan_id
        self.policies = policies
        self.session_id = session_id
        self.status = AgentStatus.IDLE
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.created_at = datetime.utcnow().isoformat()
        self.task_handle: Optional[asyncio.Task] = None

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "session_id": self.session_id,
            "policies": self.policies,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
        }


registry: dict[str, MitreScanRecord] = {}


async def run_mitre_probes(record: MitreScanRecord):
    record.status = AgentStatus.RUNNING
    all_results = []
    try:
        for action in record.policies:
            result = await run_one_mitre(action, session_id=record.session_id)
            all_results.append(result)
        record.result = json.dumps(all_results)
        record.status = AgentStatus.DONE
    except Exception as exc:
        record.error = str(exc)
        record.status = AgentStatus.ERROR


class MitreScanRequest(BaseModel):
    policies: list[str]


# ── Probe catalogue ────────────────────────────────────────────


@router.get("/probes")
async def list_mitre_probes():
    """Return the full MITRE ATLAS probe catalogue (no browser required)."""
    probes = get_mitre_probes()
    return [
        {
            "action": meta["action"],
            "mitre": meta["mitre"],
            "description": meta["description"],
        }
        for meta in probes.values()
    ]


# ── Scan lifecycle ─────────────────────────────────────────────


@router.get("/scans")
async def list_scans():
    return [r.to_dict() for r in registry.values()]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    record = registry.get(scan_id)
    if not record:
        raise HTTPException(404, "Scan not found")
    return record.to_dict()


@router.post("/scan", status_code=201)
async def start_mitre_scan(body: MitreScanRequest, background_tasks: BackgroundTasks):
    if not browser_mod.ready:
        raise HTTPException(
            400, "Browser not ready. Call /session/start and /session/confirm first."
        )
    scan_id = str(uuid.uuid4())
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    record = MitreScanRecord(
        scan_id=scan_id, policies=body.policies, session_id=session_id
    )
    registry[scan_id] = record
    task = asyncio.ensure_future(run_mitre_probes(record))
    record.task_handle = task
    return record.to_dict()


@router.post("/scan/all", status_code=201)
async def start_full_mitre_scan(background_tasks: BackgroundTasks):
    """Run every registered MITRE ATLAS probe."""
    if not browser_mod.ready:
        raise HTTPException(
            400, "Browser not ready. Call /session/start and /session/confirm first."
        )
    all_actions = list(get_mitre_probes().keys())
    scan_id = str(uuid.uuid4())
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    record = MitreScanRecord(
        scan_id=scan_id, policies=all_actions, session_id=session_id
    )
    registry[scan_id] = record
    task = asyncio.ensure_future(run_mitre_probes(record))
    record.task_handle = task
    return record.to_dict()


@router.post("/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    record = registry.get(scan_id)
    if not record:
        raise HTTPException(404, "Scan not found")
    if record.status not in (AgentStatus.IDLE, AgentStatus.RUNNING):
        return record.to_dict()

    if record.task_handle and not record.task_handle.done():
        record.task_handle.cancel()
        try:
            await record.task_handle
        except (asyncio.CancelledError, Exception):
            pass

    record.status = AgentStatus.STOPPED
    logger.info("MITRE scan %s stopped by request", scan_id)
    return record.to_dict()


@router.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str):
    if scan_id not in registry:
        raise HTTPException(404, "Scan not found")

    async def generate():
        while True:
            record = registry.get(scan_id)
            if not record:
                break
            try:
                yield f"data: {json.dumps(record.to_dict())}\n\n"
            except Exception:
                break
            if record.status in (
                AgentStatus.DONE,
                AgentStatus.ERROR,
                AgentStatus.STOPPED,
            ):
                break
            await asyncio.sleep(1)

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    record = registry.pop(scan_id, None)
    if not record:
        raise HTTPException(404, "Scan not found")
    return {"scan_id": scan_id, "message": "removed"}
