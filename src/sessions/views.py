from typing import Optional, Any
from datetime import datetime, timezone
import logging
from recon.vulnerability_analysis import find_potential_vulnerabilities
from recon.profiling import profile_target
from schemas import (
    AgentProfile,
    InterfaceMap,
    GoalRequest,
    AnalyseRequest,
    VulnerabilityReport,
)
from sessions.models import StartRequest, GenerateRequest
from recon.interface_mapping import map_interface
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from probes.execute import run_all, run_one
from probes.generate import generate_all
from pydantic import BaseModel, HttpUrl
from probes.registry import get_probes
from probes.utils import get_probe_totals
from recon.agent import run_goal
from browser_use import Agent
from agents.models import AgentRecord, AgentStatus, registry
from pathlib import Path
from urllib.parse import urlparse
import websockets
import browser
import asyncio
import json
import uuid
import re

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/session")


def safe_return(result):
    if hasattr(result, "model_dump"):
        return result.model_dump()
    return result


def save_recon_data(key: str, data: Any):
    if not browser.session_id:
        return

    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    file_path = logs_dir / f"{key}_{browser.session_id}.json"

    output = {
        "session_id": browser.session_id,
        "target_name": browser.target_name,
        "target_url": browser.target_url,
        "timestamp": datetime.now().isoformat(),
        "data": safe_return(data),
    }

    file_path.write_text(json.dumps(output, indent=2), encoding="utf-8")


def load_log(key: str):
    if not browser.session_id:
        return None
    p = Path("logs") / f"{key}_{browser.session_id}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("data")
    except Exception as e:
        logger.warning(f"Failed to load {key} log: {e}")
        return None


@router.post("/start")
async def start(body: StartRequest):
    await browser.start(str(body.url), name=body.name)
    return {"status": "browser_open"}


@router.get("/cdp-url")
async def get_cdp_url():
    """Get the Chrome DevTools Protocol WebSocket URL for the current browser session."""
    cdp_url = getattr(browser.instance, "cdp_url", None)
    if cdp_url:
        # Rewrite internal ws://localhost:PORT/... to a server-relative proxy path
        cdp_url = re.sub(
            r"^ws://(?:localhost|127\.0\.0\.1):(\d+)", r"/session/cdp-proxy/\1", cdp_url
        )
    return {"cdp_url": cdp_url}


@router.websocket("/cdp-proxy/{path:path}")
async def cdp_proxy(client_ws: WebSocket, path: str):
    """Proxy WebSocket connections to the local Chromium CDP endpoint.
    The path is expected to be: <port>/devtools/...
    e.g. /session/cdp-proxy/9222/devtools/browser/<id>
    """
    await client_ws.accept()
    cdp_url = getattr(browser.instance, "cdp_url", None)
    if not cdp_url:
        await client_ws.close(code=1011, reason="No browser session active")
        return

    # Validate that the requested port matches the actual CDP port (prevent SSRF)
    parsed = urlparse(cdp_url)
    expected_port = str(parsed.port) if parsed.port else None
    request_port = path.split("/", 1)[0]
    if not expected_port or request_port != expected_port:
        await client_ws.close(code=1008, reason="Invalid CDP target")
        return

    target_url = f"ws://localhost:{path}"
    try:
        async with websockets.connect(
            target_url,
            open_timeout=10,
            max_size=16 * 1024 * 1024,  # 16 MB — CDP can send large payloads
        ) as cdp_ws:

            async def client_to_cdp():
                try:
                    while True:
                        msg = await client_ws.receive()
                        if msg.get("text") is not None:
                            await cdp_ws.send(msg["text"])
                        elif msg.get("bytes") is not None:
                            await cdp_ws.send(msg["bytes"])
                        # {"type": "websocket.disconnect"} is handled by
                        # FastAPI raising WebSocketDisconnect before we get here
                except WebSocketDisconnect:
                    logger.debug("Client disconnected from CDP proxy")
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"client→CDP relay error: {e}")

            async def cdp_to_client():
                try:
                    async for message in cdp_ws:
                        if isinstance(message, str):
                            await client_ws.send_text(message)
                        else:
                            await client_ws.send_bytes(message)
                except websockets.exceptions.ConnectionClosed:
                    logger.debug("CDP WebSocket closed")
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"CDP→client relay error: {e}")

            # Run both directions; when either finishes, cancel the other
            tasks = [
                asyncio.create_task(client_to_cdp(), name="client→cdp"),
                asyncio.create_task(cdp_to_client(), name="cdp→client"),
            ]
            try:
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    except (
        websockets.exceptions.InvalidURI,
        websockets.exceptions.InvalidHandshake,
    ) as e:
        logger.warning(f"CDP proxy connection refused: {e}")
        await safe_close(client_ws, f"Cannot reach CDP: {e}")
    except asyncio.TimeoutError:
        logger.warning("CDP proxy upstream connection timed out")
        await safe_close(client_ws, "CDP connection timed out")
    except Exception as e:
        logger.warning(f"CDP proxy error: {e}")
        await safe_close(client_ws, str(e))


async def safe_close(ws: WebSocket, reason: str, code: int = 1011):
    """Close a WebSocket, truncating the reason to the 123-byte protocol limit."""
    try:
        reason_bytes = reason.encode("utf-8")[:123]
        await ws.close(code=code, reason=reason_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        pass


@router.post("/confirm")
async def confirm():
    await browser.confirm()
    return {"status": "authenticated", "storage_state": "auth.json"}


@router.get("/status")
async def status():
    return {"authenticated": browser.ready}


@router.post("/find-chat")
async def find_chat():
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    agent = Agent(
        task=f"Go to {browser.target_url}. Does this app have an AI chat interface? If yes describe it. If no, say NO_CHAT_INTERFACE.",
        llm=browser.llm,
        browser_session=browser.instance,
        max_steps=8,
    )
    history = await agent.run()
    result = history.final_result() or ""
    return {
        "chat_detected": "no_chat_interface" not in result.lower(),
        "details": result,
    }


@router.post("/map-interface")
async def run_interface_mapping():
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")

    agent_id = str(uuid.uuid4())
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    record = AgentRecord(
        agent_id=agent_id, policies=["map-interface"], session_id=session_id
    )
    registry[agent_id] = record

    async def bg_task():
        record.status = AgentStatus.RUNNING
        try:
            result = await map_interface()
            save_recon_data("interface", result)
            record.result = json.dumps(safe_return(result))
            record.status = AgentStatus.DONE
        except asyncio.CancelledError:
            record.status = AgentStatus.STOPPED
            logger.info("Agent %s cancelled", agent_id)
        except Exception as exc:
            record.error = str(exc)
            record.status = AgentStatus.ERROR

    task = asyncio.ensure_future(bg_task())
    record.task_handle = task
    return record.to_dict()


@router.get("/map-interface/{agent_id}")
async def get_map_interface_status(agent_id: str):
    record = registry.get(agent_id)
    if not record:
        raise HTTPException(404, "Not Found")
    return record.to_dict()


@router.post("/profile")
async def run_usecase_identification():
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")

    agent_id = str(uuid.uuid4())
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    record = AgentRecord(agent_id=agent_id, policies=["profile"], session_id=session_id)
    registry[agent_id] = record

    async def bg_task():
        record.status = AgentStatus.RUNNING
        try:
            full = await profile_target()
            profile = full.to_agent_profile()
            tools = full.to_tool_discovery()
            save_recon_data("profile", profile)
            save_recon_data("tools", tools)
            record.result = json.dumps(
                {"profile": safe_return(profile), "tools": safe_return(tools)}
            )
            record.status = AgentStatus.DONE
        except asyncio.CancelledError:
            record.status = AgentStatus.STOPPED
            logger.info("Agent %s cancelled", agent_id)
        except Exception as exc:
            record.error = str(exc)
            record.status = AgentStatus.ERROR

    task = asyncio.ensure_future(bg_task())
    record.task_handle = task
    return record.to_dict()


@router.get("/profile/{agent_id}")
async def get_profile_status(agent_id: str):
    record = registry.get(agent_id)
    if not record:
        raise HTTPException(404, "Not Found")
    return record.to_dict()


@router.post("/discover-tools")
async def run_tool_discovery():
    cached = load_log("tools")
    if cached:
        return cached
    # if not browser.ready:
    #     raise HTTPException(400, "Not authenticated")
    full = await profile_target()
    profile = full.to_agent_profile()
    tools = full.to_tool_discovery()
    save_recon_data("profile", profile)
    save_recon_data("tools", tools)
    return safe_return(tools)


@router.post("/generate-payloads")
async def generate_payloads(body: Optional[GenerateRequest] = None):
    app_profile = (
        body.profile.model_dump() if body and body.profile else load_log("profile")
    )
    interface_map = (
        body.interface.model_dump()
        if body and body.interface
        else load_log("interface")
    )
    goal = body.goal if body and body.goal else None
    vulnerabilities = (
        body.vulnerabilities
        if body and body.vulnerabilities
        else load_log("vulnerabilities")
    )

    summary = generate_all(
        app_profile=app_profile,
        interface_map=interface_map,
        goal=goal,
        vulnerabilities=vulnerabilities,
    )
    return {"status": "done", "summary": summary}


@router.get("/probes")
async def list_probes():
    return {"probes": get_probes()}


@router.post("/run")
async def run():
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    return await run_all()


@router.post("/run/{action}")
async def run_single(action: str):
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    result = await run_one(action)
    if result.get("error") and not result.get("results"):
        raise HTTPException(404, result["error"])
    return result


@router.post("/analyse")
async def analyse(body: Optional[AnalyseRequest] = None):
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")

    profile_raw = body.profile if body and body.profile else load_log("profile")
    interface_raw = body.interface if body and body.interface else load_log("interface")

    profile = (
        AgentProfile.model_validate(profile_raw)
        if isinstance(profile_raw, dict)
        else profile_raw
    )
    interface = (
        InterfaceMap.model_validate(interface_raw)
        if isinstance(interface_raw, dict)
        else interface_raw
    )

    result = await find_potential_vulnerabilities(profile, interface)
    save_recon_data("vulnerabilities", result)
    return safe_return(result)


@router.post("/run-goal")
async def run_goal_endpoint(body: GoalRequest):
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")

    profile_raw = body.profile if body.profile else load_log("profile")
    interface_raw = body.interface if body.interface else load_log("interface")
    vuln_raw = body.vuln_report if body.vuln_report else load_log("vulnerabilities")

    profile = (
        AgentProfile.model_validate(profile_raw)
        if isinstance(profile_raw, dict)
        else profile_raw
    )
    interface = (
        InterfaceMap.model_validate(interface_raw)
        if isinstance(interface_raw, dict)
        else interface_raw
    )
    vuln_report = (
        VulnerabilityReport.model_validate(vuln_raw)
        if isinstance(vuln_raw, dict)
        else vuln_raw
    )

    agent_id = str(uuid.uuid4())
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    record = AgentRecord(
        agent_id=agent_id, policies=["run-goal"], session_id=session_id
    )
    registry[agent_id] = record

    async def bg_task():
        record.status = AgentStatus.RUNNING
        try:
            result = await run_goal(
                goal=body.goal,
                policies=body.policies,
                profile=profile,
                interface=interface,
                vuln_report=vuln_report,
                max_iterations=body.max_iterations,
                session_id=session_id,
            )
            record.result = json.dumps(safe_return(result))
            record.status = AgentStatus.DONE
        except asyncio.CancelledError:
            record.status = AgentStatus.STOPPED
            logger.info("Agent %s cancelled", agent_id)
        except Exception as exc:
            record.error = str(exc)
            record.status = AgentStatus.ERROR

    task = asyncio.ensure_future(bg_task())
    record.task_handle = task
    return record.to_dict()


@router.get("/logs")
async def list_logs():
    logs_dir = Path("logs")
    if not logs_dir.exists():
        return {"sessions": []}

    sessions = []
    for p in logs_dir.glob("attack_log_*.json"):
        session_id = p.stem.replace("attack_log_", "")
        try:
            with open(p, "r", encoding="utf-8") as f:
                first_line = f.readline()
                if first_line:
                    data = json.loads(first_line)
                    sessions.append(
                        {
                            "session_id": session_id,
                            "target_name": data.get("target_name", "Unknown"),
                            "target_url": data.get("target_url", "Unknown"),
                            "timestamp": data.get("timestamp", ""),
                        }
                    )
                else:
                    sessions.append(
                        {
                            "session_id": session_id,
                            "target_name": "Unknown",
                            "target_url": "Unknown",
                            "timestamp": "",
                        }
                    )
        except Exception:
            sessions.append(
                {
                    "session_id": session_id,
                    "target_name": "Unknown",
                    "target_url": "Unknown",
                    "timestamp": "",
                }
            )

    sessions.sort(key=lambda x: x["session_id"], reverse=True)
    return {"sessions": sessions}


@router.get("/results")
async def get_results(session_id: Optional[str] = None):
    if session_id:
        path = Path(f"logs/attack_log_{session_id}.json")
    else:
        path = Path("results.jsonl")
        if not path.exists():
            logs_dir = Path("logs")
            if logs_dir.exists():
                log_files = sorted(logs_dir.glob("attack_log_*.json"), reverse=True)
                if log_files:
                    path = log_files[0]

    if not path.exists():
        return {"rows": []}
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    totals = get_probe_totals()
    return {"rows": rows, "totals": totals}
