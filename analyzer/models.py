from sqlalchemy import create_engine, Column, String, JSON, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import insert, select
from pydantic import BaseModel, Field
from typing import Literal, Optional


class Report(BaseModel):
    """Analysis of LLM I/O"""
    threat: bool = Field(..., description="Whether the text contains an attack")
    rating: float = Field(..., description="The threat's rating out of 10")
    category: Optional[str] = Field(
        None,
        description="category of the attack ({category: category description})"
    )
    description: str = Field(..., description="The description of the attack")

DATABASE_URL = "sqlite:///scan.db"

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    scan_id = Column(String, primary_key=True, index=True)
    input = Column(String, nullable=True)
    output = Column(String, nullable=True)
    scans = Column(JSON, default=dict)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


Base.metadata.create_all(bind=engine)

# -------------------------
# Helpers
# -------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def normalize_scans(node, out: list):
    if isinstance(node, dict):
        if "rating" in node:
            out.append(node)
        else:
            for v in node.values():
                normalize_scans(v, out)

def deep_update(dst: dict, src: dict):
    for k, v in src.items():
        if isinstance(v, dict):
            dst[k] = deep_update(dst.get(k, {}), v)
        else:
            dst[k] = v
    return dst


def get_scan_id(traceparent: str) -> str:
    parts = traceparent.split("-")
    if len(parts) < 2 or not parts[1]:
        raise ValueError("Invalid traceparent")

    return parts[1]


# -------------------------
# Main store function
# -------------------------

def store(scan_id: str, text_type: Literal["input", "output"], text: dict, scan_results: dict):
    with SessionLocal.begin() as session:

        stmt = insert(Scan).values(
            scan_id=scan_id,
            input=None,
            output=None,
            scans={}
        ).prefix_with("OR IGNORE")
        
        result = session.execute(stmt)

        scan = session.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        ).scalar_one()

        setattr(scan, text_type, text)

        current = dict(scan.scans) if scan.scans else {}
        
        report = {text_type: scan_results}
        
        deep_update(current, report)

        scan.scans = current

        result = {
            "input": scan.input,
            "output": scan.output,
            "scans": scan.scans,
        }
        
        return result