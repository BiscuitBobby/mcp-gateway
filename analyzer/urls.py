from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from analyzer.models import Scan, get_db, normalize_scans
from analyzer.graphs import init_graph_state, build_graph_payload, finalize_graph
from analyzer.views import list_scans, status

router = APIRouter()

@router.get("/status")
async def status_endpoint(id: str):
    return status(id)


@router.get("/scan/{scan_id}/graphs")
def get_graphs(scan_id: str, db: Session = Depends(get_db)):
    scans_json = db.execute(
        select(Scan.scans).where(Scan.scan_id == scan_id)
    ).scalar_one()

    normalized = []
    normalize_scans(scans_json or {}, normalized)

    graph_state = init_graph_state()
    build_graph_payload(normalized, graph_state)

    return {
        "scan_id": scan_id,
        "total_scans": len(normalized),
        "threats": graph_state["threats"],
        "graphs": finalize_graph(graph_state),
        "descriptions": [s.get("description") for s in normalized],
    }


@router.get("/scans/graphs")
def get_all_graphs(db: Session = Depends(get_db)):
    """
    Streams ALL scans without loading entire table into memory.
    """

    rows = db.execute(select(Scan.scans)).scalars()

    graph_state = init_graph_state()

    total_scans = 0

    for scans_json in rows:
        normalized = []
        normalize_scans(scans_json or {}, normalized)

        total_scans += len(normalized)

        # Incremental aggregation
        build_graph_payload(normalized, graph_state)

    return {
        "total_scans": total_scans,
        "threats": graph_state["threats"],
        "graphs": finalize_graph(graph_state),
    }

@router.get("/scans/cursor")
def reports(limit: int = Query(20, ge=1, le=100),
    cursor: str | None = None,
    db: Session = Depends(get_db)):
    return list_scans(limit, cursor, db)
    
