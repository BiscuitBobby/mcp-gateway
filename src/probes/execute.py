from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import browser
from probes.registry import get_probes

logger = logging.getLogger(__name__)


class ProbeSession:
    """Minimal session object every probe expects."""

    def __init__(self, session_id: Optional[str] = None):
        self.browser = browser.instance
        self.target_url = browser.target_url
        self.target_name = getattr(browser, "target_name", "Target")
        self.session_id = (
            session_id
            or browser.session_id
            or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        )
        self.chat_detected = True
        self.evidence: list[dict] = []


async def reset_chat() -> None:
    pass


async def run_all(session_id: Optional[str] = None) -> dict[str, Any]:
    probes = get_probes()
    all_results = []

    for name, meta in probes.items():
        probe = meta["instance"]

        if probe is None:
            logger.warning("[executor] No probe class for action: %s", name)
            all_results.append(
                {
                    "probe": name,
                    "action": meta["action"],
                    "owasp": meta["owasp"],
                    "success": False,
                    "results": [],
                    "error": f"No handler for action '{name}'",
                }
            )
            continue

        logger.info("[executor] Running: %s", name)
        await reset_chat()
        session = ProbeSession(session_id=session_id)

        try:
            result = await probe.run(session=session, llm=browser.llm)
            all_results.append(
                {
                    "probe": name,
                    "action": meta["action"],
                    "owasp": meta["owasp"],
                    "success": result.get("success", False),
                    "results": result.get("results", []),
                    "error": result.get("error"),
                }
            )
        except Exception as exc:
            logger.exception("[executor] %s raised: %s", name, exc)
            all_results.append(
                {
                    "probe": name,
                    "action": meta["action"],
                    "owasp": meta["owasp"],
                    "success": False,
                    "results": [],
                    "error": str(exc),
                }
            )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "probes_run": len(all_results),
        "results": all_results,
    }


async def run_one(action: str, session_id: Optional[str] = None) -> dict[str, Any]:
    probes = get_probes()
    meta = next((m for m in probes.values() if m["action"] == action), None)

    if meta is None:
        return {"success": False, "error": f"Unknown action: '{action}'"}

    probe = meta["instance"]
    if probe is None:
        return {"success": False, "error": f"No handler for action: '{action}'"}

    await reset_chat()
    session = ProbeSession(session_id=session_id)

    try:
        result = await probe.run(session=session, llm=browser.llm)
        return {
            "probe": action,
            "owasp": meta["owasp"],
            "session_id": session.session_id,
            "success": result.get("success", False),
            "results": result.get("results", []),
            "error": result.get("error"),
        }
    except Exception as exc:
        logger.exception("[executor] %s raised: %s", action, exc)
        return {
            "probe": action,
            "owasp": meta["owasp"],
            "session_id": session.session_id,
            "success": False,
            "results": [],
            "error": str(exc),
        }
