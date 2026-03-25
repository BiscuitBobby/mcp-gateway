from recon.vulnerability_analysis import find_potential_vulnerabilities
from recon.profiling import identify_usecase, discover_tools
from schemas import AgentProfile, InterfaceMap, GoalRequest
from recon.interface_mapping import map_interface
from fastapi import APIRouter, HTTPException
from probes.execute import run_all, run_one
from probes.generate import generate_all
from pydantic import BaseModel, HttpUrl
from probes.registry import get_probes
from recon.agent import run_goal
from browser_use import Agent
from pathlib import Path
import browser
import json

router = APIRouter(prefix="/session")


class StartRequest(BaseModel):
    url: HttpUrl


class GenerateRequest(BaseModel):
    profile: AgentProfile
    interface: InterfaceMap


def safe_return(result):
    if hasattr(result, "model_dump"):
        return result.model_dump()
    return result


@router.post("/start")
async def start(body: StartRequest):
    await browser.start(str(body.url))
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
        browser=browser.instance,
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
    return safe_return(await map_interface())


@router.post("/profile")
async def run_usecase_identification():
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    return safe_return(await identify_usecase())


@router.post("/discover-tools")
async def run_tool_discovery():
    # if not browser.ready:
    #     raise HTTPException(400, "Not authenticated")
    return safe_return(await discover_tools())


@router.post("/generate-payloads")
async def generate_payloads(body: GenerateRequest):
    summary = generate_all(
        app_profile=body.profile.model_dump(),
        model_profile=body.interface.model_dump(),
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
async def analyse(profile: AgentProfile, interface: InterfaceMap):
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    return safe_return(await find_potential_vulnerabilities(profile, interface))


@router.post("/run-goal")
async def run_goal_endpoint(body: GoalRequest):
    if not browser.ready:
        raise HTTPException(400, "Not authenticated")
    augmented_goal = (
        f"Goal:\n{body.goal}\n\n"
        f"Agent Profile:\n{body.profile.model_dump_json(indent=2)}\n\n"
        f"Interface:\n{body.interface.model_dump_json(indent=2)}"
    )
    return await run_goal(goal=augmented_goal, max_iterations=body.max_iterations)


@router.get("/results")
async def get_results():
    path = Path("results.jsonl")
    if not path.exists():
        return {"rows": []}
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return {"rows": rows}


@router.post("/stop")
async def stop():
    await browser.stop()
    return {"status": "stopped"}
