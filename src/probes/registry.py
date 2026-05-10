from pathlib import Path

from dotenv import load_dotenv

from probes.base import StandardProbe
from probes.probe_configs import OWASP_PROBES, MITRE_PROBES

# Custom probes with unique logic — kept as standalone files
from probes.owasp.rag_poisoning.rag_poisoning import RagPoisoningProbe
from probes.owasp.tool_misuse.tool_misuse import ToolMisuseProbe

load_dotenv()

# ── Probe directory roots ─────────────────────────────────────

_PROBES_DIR = Path(__file__).parent
_OWASP_DIR = _PROBES_DIR / "owasp"
_MITRE_DIR = _PROBES_DIR / "mitre"

# ── Dynamic StandardProbe factories ───────────────────────────


def _make_owasp_probe(name: str, config: dict) -> StandardProbe:
    """Create a StandardProbe instance for an OWASP probe."""
    probe_dir = _OWASP_DIR / name
    probe_dir.mkdir(parents=True, exist_ok=True)

    cls = type(
        f"{name.title().replace('_', '')}Probe",
        (StandardProbe,),
        {
            "name": name,
            "owasp_category": config["owasp_category"],
            "record_type": config["record_type"],
            "prompts_file": probe_dir / config["output_file"],
        },
    )
    return cls()


def _make_mitre_probe(name: str, config: dict) -> StandardProbe:
    """Create a StandardProbe instance for a MITRE probe."""
    dir_name = config.get("dir_name", name)
    probe_dir = _MITRE_DIR / dir_name
    probe_dir.mkdir(parents=True, exist_ok=True)

    cls = type(
        f"{name.title().replace('_', '')}Probe",
        (StandardProbe,),
        {
            "name": name,
            "mitre_category": config["mitre_category"],
            "record_type": config["record_type"],
            "prompts_file": probe_dir / config["output_file"],
        },
    )
    return cls()


# ── Registries ─────────────────────────────────────────────────

_owasp_registry = None
_mitre_registry = None


def get_owasp_probes():
    global _owasp_registry
    if _owasp_registry is not None:
        return _owasp_registry

    _owasp_registry = {}

    for name, config in OWASP_PROBES.items():
        if config.get("custom_probe"):
            # Custom probes are imported directly
            if name == "rag_poisoning":
                instance = RagPoisoningProbe()
            elif name == "tool_misuse":
                instance = ToolMisuseProbe()
            else:
                continue
        else:
            instance = _make_owasp_probe(name, config)

        _owasp_registry[name] = {
            "action": name,
            "owasp": config["owasp_category"],
            "description": config.get("description", ""),
            "prompts_file": config["output_file"],
            "instance": instance,
        }

    return _owasp_registry


def get_mitre_probes():
    global _mitre_registry
    if _mitre_registry is not None:
        return _mitre_registry

    _mitre_registry = {}

    for name, config in MITRE_PROBES.items():
        instance = _make_mitre_probe(name, config)

        _mitre_registry[name] = {
            "action": name,
            "mitre": config["mitre_category"],
            "description": config.get("description", ""),
            "instance": instance,
        }

    return _mitre_registry


def get_probes():
    return {"owasp": get_owasp_probes(), "mitre": get_mitre_probes()}
