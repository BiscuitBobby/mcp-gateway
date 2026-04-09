from typing import Optional, Any
from datetime import datetime
import logging
from recon.vulnerability_analysis import find_potential_vulnerabilities
from recon.profiling import profile_target, identify_usecase, discover_tools
from schemas import AgentProfile, InterfaceMap, GoalRequest, AnalyseRequest, VulnerabilityReport
from recon.interface_mapping import map_interface
from fastapi import APIRouter, HTTPException
from probes.execute import run_all, run_one
from probes.generate import generate_all
from pydantic import BaseModel, HttpUrl
from probes.registry import get_probes
from probes.utils import get_probe_totals
from recon.agent import run_goal
from browser_use import Agent
from pathlib import Path
import browser
import json

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/session")


class StartRequest(BaseModel):
    url: HttpUrl
    name: Optional[str] = None


class GenerateRequest(BaseModel):
    profile: Optional[AgentProfile] = None
    interface: Optional[InterfaceMap] = None
    goal: Optional[str] = None
    vulnerabilities: Optional[Any] = None


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
    return {"cdp_url": getattr(browser.instance, "cdp_url", None)}


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
    result = await map_interface()
    save_recon_data("interface", result)
    return safe_return(result)


@router.post("/profile")
async def run_usecase_identification():
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    full = await profile_target()
    profile = full.to_agent_profile()
    tools = full.to_tool_discovery()
    save_recon_data("profile", profile)
    save_recon_data("tools", tools)
    return {"profile": safe_return(profile), "tools": safe_return(tools)}


@router.post("/discover-tools")
async def run_tool_discovery():
    cached = load_log("tools")
    if cached:
        return cached
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    full = await profile_target()
    profile = full.to_agent_profile()
    tools = full.to_tool_discovery()
    save_recon_data("profile", profile)
    save_recon_data("tools", tools)
    return safe_return(tools)


@router.post("/generate-payloads")
async def generate_payloads(body: Optional[GenerateRequest] = None):
    app_profile = body.profile.model_dump() if body and body.profile else load_log("profile")
    model_profile = body.interface.model_dump() if body and body.interface else load_log("interface")
    goal = body.goal if body and body.goal else None
    vulnerabilities = body.vulnerabilities if body and body.vulnerabilities else load_log("vulnerabilities")

    summary = generate_all(
        app_profile=app_profile,
        model_profile=model_profile,
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

    profile = AgentProfile.model_validate(profile_raw) if isinstance(profile_raw, dict) else profile_raw
    interface = InterfaceMap.model_validate(interface_raw) if isinstance(interface_raw, dict) else interface_raw

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

    profile = AgentProfile.model_validate(profile_raw) if isinstance(profile_raw, dict) else profile_raw
    interface = InterfaceMap.model_validate(interface_raw) if isinstance(interface_raw, dict) else interface_raw
    vuln_report = VulnerabilityReport.model_validate(vuln_raw) if isinstance(vuln_raw, dict) else vuln_raw

    return await run_goal(
        goal=body.goal,
        profile=profile,
        interface=interface,
        vuln_report=vuln_report,
        max_iterations=body.max_iterations,
    )


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


@router.post("/stop")
async def stop():
    await browser.stop()
    return {"status": "stopped"}