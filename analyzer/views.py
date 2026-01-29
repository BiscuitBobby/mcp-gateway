import asyncio
from typing import Literal
from fastapi.concurrency import run_in_threadpool

from analyzer.models import store, database, get_scan_id

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
                "detected": detected
            }
        }

    record = store(scan_id, text_type, text, results)

    logger.info(f"scan:{record}")


# --------------------
# async wrapper
# --------------------

def run_scan(logger, traceparent, text_type, text):
    asyncio.create_task(
        run_in_threadpool(scan, logger, traceparent, text_type, text)
    )


def status(scan_id: str):
    return database.get(scan_id)