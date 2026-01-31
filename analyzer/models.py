from typing import Literal
from sqlalchemy import insert, select
from sqlalchemy import create_engine, Column, String, JSON
from sqlalchemy.orm import declarative_base, sessionmaker


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


Base.metadata.create_all(bind=engine)

# -------------------------
# Helpers
# -------------------------

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

def store(scan_id: str, text_type: Literal["input", "output"], text: str, scan_results: dict):
    with SessionLocal.begin() as session:
        # Atomic create-if-not-exists
        stmt = insert(Scan).values(
            scan_id=scan_id,
            input=None,
            output=None,
            scans={}
        ).prefix_with("OR IGNORE")

        session.execute(stmt)

        # Now it DEFINITELY exists
        scan = session.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        ).scalar_one()

        # Update input/output
        setattr(scan, text_type, text)

        # Merge scans
        current = scan.scans or {}
        report = {"scans": scan_results}
        deep_update(current, report)

        scan.scans = current

        return {
            "input": scan.input,
            "output": scan.output,
            "scans": scan.scans,
        }

