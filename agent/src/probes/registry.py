from dotenv import load_dotenv
from probes.probe_configs import OWASP_PROBES, MITRE_PROBES

# OWASP probes
from probes.owasp.prompt_injection.prompt_injection import PromptInjection
from probes.owasp.sensitive_information_disclosure.sensitive_information_disclosure import (
    SensitiveInformationDisclosure,
)
from probes.owasp.data_exfiltration.data_exfiltration import DataExfiltration
from probes.owasp.excessive_agency.excessive_agency import ExcessiveAgency
from probes.owasp.improper_output_handling.improper_output_handling import (
    ImproperOutputHandling,
)
from probes.owasp.misinformation.misinformation import Misinformation
from probes.owasp.rag_poisoning.rag_poisoning import RagPoisoning
from probes.owasp.tool_misuse.tool_misuse import ToolMisuse

# MITRE probes
from probes.mitre.ai_attack_staging.attack_staging import AttackStaging
from probes.mitre.collection.collection import Collection
from probes.mitre.credential_extraction.credential_extraction import (
    CredentialExtraction,
)
from probes.mitre.discovery.discovery import Discovery
from probes.mitre.evasion_techniques.evasion_techniques import EvasionTechniques
from probes.mitre.impact.impact import Impact
from probes.mitre.lateral_movement.lateral_movement import LateralMovement
from probes.mitre.reconnaissance.reconnaissance import Reconnaissance
from probes.mitre.user_execution.user_execution import UserExecution

load_dotenv()

# ── Probe instance mapping ────────────────────────────────────

# Map probe names to their class instances
OWASP_PROBE_INSTANCES = {
    "prompt_injection": PromptInjection(),
    "sensitive_information_disclosure": SensitiveInformationDisclosure(),
    "data_exfiltration": DataExfiltration(),
    "excessive_agency": ExcessiveAgency(),
    "improper_output_handling": ImproperOutputHandling(),
    "misinformation": Misinformation(),
    "rag_poisoning": RagPoisoning(),
    "tool_misuse": ToolMisuse(),
}

MITRE_PROBE_INSTANCES = {
    "attack_staging": AttackStaging(),
    "collection": Collection(),
    "credential_extraction": CredentialExtraction(),
    "discovery": Discovery(),
    "evasion_techniques": EvasionTechniques(),
    "impact": Impact(),
    "lateral_movement": LateralMovement(),
    "reconnaissance": Reconnaissance(),
    "user_execution": UserExecution(),
}

# ── Registries ─────────────────────────────────────────────────

owasp_registry = None
mitre_registry = None


def get_owasp_probes():
    global owasp_registry
    if owasp_registry is not None:
        return owasp_registry

    owasp_registry = {}

    for name, config in OWASP_PROBES.items():
        instance = OWASP_PROBE_INSTANCES.get(name)
        if instance is None:
            continue

        owasp_registry[name] = {
            "action": name,
            "owasp": config["owasp_category"],
            "description": config.get("description", ""),
            "prompts_file": config["output_file"],
            "instance": instance,
        }

    return owasp_registry


def get_mitre_probes():
    global mitre_registry
    if mitre_registry is not None:
        return mitre_registry

    mitre_registry = {}

    for name, config in MITRE_PROBES.items():
        instance = MITRE_PROBE_INSTANCES.get(name)
        if instance is None:
            continue

        mitre_registry[name] = {
            "action": name,
            "mitre": config["mitre_category"],
            "description": config.get("description", ""),
            "instance": instance,
        }

    return mitre_registry


def get_probes():
    return {"owasp": get_owasp_probes(), "mitre": get_mitre_probes()}
