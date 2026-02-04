from fastapi.concurrency import run_in_threadpool
import asyncio
from sqlalchemy.orm import Session
from analyzer.filters import scan
from analyzer.models import (
    SessionLocal,
    Scan,
    get_db,
)
from sqlalchemy import select, and_, or_
from datetime import datetime
from fastapi import Depends, Query
import base64
import json


def run_scan(logger, traceparent, text_type, text):
    asyncio.create_task(
        run_in_threadpool(scan, logger, traceparent, text_type, text)
    )

def encode_cursor(created_at: datetime, scan_id: str) -> str:
    payload = {
        "created_at": created_at.isoformat(),
        "scan_id": scan_id,
    }
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).decode()


def decode_cursor(cursor: str):
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    data = json.loads(raw)
    return datetime.fromisoformat(data["created_at"]), data["scan_id"]

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

def build_graph_payload(scans: list[dict]) -> dict:
    ratings = [s["rating"] for s in scans]
    threats = [s["threat"] for s in scans]

    threat_count = sum(1 for t in threats if t)
    safe_count = len(threats) - threat_count

    graphs = {}

    # ---- Graph 1: Threat vs Safe ----
    graphs["threat_distribution"] = {
        "type": "pie",
        "labels": ["Threat", "Safe"],
        "values": [threat_count, safe_count]
    }

    # ---- Graph 2: Ratings ----
    graphs["ratings"] = {
        "type": "bar",
        "labels": [f"scan_{i}" for i in range(len(ratings))],
        "values": ratings
    }

    # ---- Graph 3: Severity Histogram ----
    buckets = [0]*11
    for r in ratings:
        buckets[int(r)] += 1

    graphs["severity_histogram"] = {
        "type": "histogram",
        "x": list(range(11)),
        "y": buckets
    }

    return graphs


def list_scans(
    limit: int = Query(20, ge=1, le=100),
    cursor: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Cursor-based pagination over scans.
    Ordered by (created_at DESC, scan_id DESC).
    """

    stmt = select(
        Scan.scan_id,
        Scan.created_at,
        Scan.updated_at,
        Scan.input,
        Scan.output,
        Scan.scans,
    ).order_by(
        Scan.created_at.desc(),
        Scan.scan_id.desc(),
    )

    if cursor:
        created_at, scan_id = decode_cursor(cursor)

        stmt = stmt.where(
            or_(
                Scan.created_at < created_at,
                and_(
                    Scan.created_at == created_at,
                    Scan.scan_id < scan_id,
                ),
            )
        )

    rows = db.execute(stmt.limit(limit + 1)).all()

    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        {
            "scan_id": r.scan_id,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
            "data": r.scans,
            "has_input": bool(r.input),
            "has_output": bool(r.output),
        }
        for r in rows
    ]

    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = encode_cursor(last.created_at, last.scan_id)

    return {
        "limit": limit,
        "next_cursor": next_cursor,
        "items": items,
    }
