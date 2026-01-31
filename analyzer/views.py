import asyncio
from typing import Literal
from fastapi.concurrency import run_in_threadpool

from analyzer.models import (
    store,
    get_scan_id,
    SessionLocal,
    Scan,
)

# pretend scanners
SCANNERS = {
    "base64_exploit": "virus",
    "sql_injection": "select",
}

# --------------------
# scanning logic
# --------------------

def scan(logger, traceparent: str, text_type: Literal["input", "output"], text):
    scan_id = get_scan_id(traceparent)

    results = {}

    text = str(text)
    for name, keyword in SCANNERS.items():
        detected = keyword.lower() in text.lower()

        results[name] = {
            text_type: {
                "status": "complete",
                "detected": detected
            }
        }

    record = store(scan_id, text_type, text, results)

    logger.info(f"scan:{record}")


def run_scan(logger, traceparent, text_type, text):
    asyncio.create_task(
        run_in_threadpool(scan, logger, traceparent, text_type, text)
    )


# --------------------
# status lookup
# --------------------

def status(scan_id: str):
    with SessionLocal() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if not scan:
            return None

        return {
            "input": scan.input,
            "output": scan.output,
            "scans": scan.scans,
        }
