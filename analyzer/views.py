from fastapi.concurrency import run_in_threadpool
import asyncio

from analyzer.filters import scan
from analyzer.models import (
    SessionLocal,
    Scan,
)


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
            "output": scan.output or None,
            "complete": scan.output is not None,
            "scans": scan.scans,
        }