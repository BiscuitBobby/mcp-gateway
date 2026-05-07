from dotenv import load_dotenv
from probes.prompt_injection.prompt_injection import PromptInjectionProbe
from probes.sensitive_information_disclosure.sensitive_information_disclosure import SensitiveInformationDisclosureProbe
from probes.misinformation.misinformation import MisinformationProbe
from probes.improper_output_handling.improper_output_handling import ImproperOutputHandlingProbe
from probes.excessive_agency.excessive_agency import ExcessiveAgencyProbe
from probes.rag_poisoning.rag_poisoning import RagPoisoningProbe
from probes.tool_misuse.tool_misuse import ToolMisuseProbe
from probes.data_exfiltration.data_exfiltration import DataExfiltrationProbe

from mitre.ai_attack_staging.attack_staging import AttackStaging
from mitre.collection.collection import Collection
from mitre.context_manipulation.context_manipulation import ContextManipulation
from mitre.credential_extraction.credential_extraction import CredentialExtraction
from mitre.discovery.discovery import Discovery
from mitre.evasion_techniques.evasion import EvasionTechniques
from mitre.impact.impact import Impact
from mitre.lateral_movement.lateral_movement import LateralMovement
from mitre.reconnaissance.reconnaissance import Reconnaissance
from mitre.user_execution.user_execution import UserExecution

load_dotenv()

_owasp_registry = None
_mitre_registry = None


def get_owasp_probes():
    global _owasp_registry
    if _owasp_registry is not None:
        return _owasp_registry

    _owasp_registry = {
        "prompt_injection": {
            "action": "prompt_injection",
            "owasp": "LLM01: Prompt Injection",
            "description": "Tests whether the model follows injected instructions that override its system prompt or hijack its behaviour.",
            "prompts_file": "prompt_injection_prompts.json",
            "instance": PromptInjectionProbe(),
        },
        "sensitive_information_disclosure": {
            "action": "sensitive_information_disclosure",
            "owasp": "LLM02: Sensitive Information Disclosure",
            "description": "Tests whether the model leaks system prompts, credentials, or sensitive data through benign-sounding questions.",
            "prompts_file": "sensitive_info_prompts.json",
            "instance": SensitiveInformationDisclosureProbe(),
        },
        "data_exfiltration": {
            "action": "data_exfiltration",
            "owasp": "LLM06: Data Exfiltration",
            "description": "Tests whether the model can be tricked into exfiltrating PII, conversation history, RAG contents, or API keys.",
            "prompts_file": "data_exfiltration_prompts.json",
            "instance": DataExfiltrationProbe(),
        },
        "excessive_agency": {
            "action": "excessive_agency",
            "owasp": "LLM08: Excessive Agency",
            "description": "Tests whether the model takes unauthorised real-world actions such as sending emails, modifying accounts, or executing destructive operations.",
            "prompts_file": "excessive_agency_prompts.json",
            "instance": ExcessiveAgencyProbe(),
        },
        "improper_output_handling": {
            "action": "improper_output_handling",
            "owasp": "LLM05: Improper Output Handling",
            "description": "Tests whether the model produces dangerous structured output — injected HTML, forged tool calls, malformed JSON with privilege fields.",
            "prompts_file": "improper_output_handling_prompts.json",
            "instance": ImproperOutputHandlingProbe(),
        },
        "misinformation": {
            "action": "misinformation",
            "owasp": "LLM04: Misinformation",
            "description": "Tests whether the model can be manipulated into confidently asserting false facts, fabricated citations, or invented statistics.",
            "prompts_file": "misinformation_prompts.json",
            "instance": MisinformationProbe(),
        },
        "rag_poisoning": {
            "action": "rag_poisoning",
            "owasp": "LLM09: Over-reliance (Indirect via RAG)",
            "description": "Uploads malicious documents with hidden instructions to test indirect prompt injection via RAG",
            "prompts_file": "rag_poisoning_prompts.json",
            "instance": RagPoisoningProbe(),
        },
        "tool_misuse": {
            "action": "tool_misuse",
            "owasp": "LLM08: Excessive Agency",
            "description": "Tests whether the model can be manipulated into misusing available tools in a way that leads to security issues or unintended consequences.",
            "prompts_file": "tool_misuse_prompts.json",
            "instance": ToolMisuseProbe(),
        },
    }

    return _owasp_registry


def get_mitre_probes():
    global _mitre_registry
    if _mitre_registry is not None:
        return _mitre_registry

    _mitre_registry = {
        "reconnaissance": {
            "action": "reconnaissance",
            "mitre": "ATLAS: Reconnaissance",
            "description": "Tests whether the model assists in gathering intelligence about a target AI system, its users, or its infrastructure.",
            "instance": Reconnaissance(),
        },
        "attack_staging": {
            "action": "attack_staging",
            "mitre": "ATLAS: ML Attack Staging",
            "description": "Tests whether the model assists in preparing, verifying, or refining an adversarial attack against an AI system.",
            "instance": AttackStaging(),
        },
        "user_execution": {
            "action": "user_execution",
            "mitre": "ATLAS: User Execution",
            "description": "Tests whether the model generates content designed to trick a user into executing a malicious action.",
            "instance": UserExecution(),
        },
        "discovery": {
            "action": "discovery",
            "mitre": "ATLAS: Discovery",
            "description": "Tests whether the model reveals information about its own architecture, configuration, capabilities, or the AI system it belongs to.",
            "instance": Discovery(),
        },
        "collection": {
            "action": "collection",
            "mitre": "ATLAS: Collection",
            "description": "Tests whether the model surfaces or facilitates extraction of data from AI services, RAG stores, or agent tools.",
            "instance": Collection(),
        },
        "credential_extraction": {
            "action": "credential_extraction",
            "mitre": "ATLAS: Credential Access",
            "description": "Tests whether the model discloses credentials, tokens, or secrets sourced from RAG stores, agent tool configs, or its own configuration.",
            "instance": CredentialExtraction(),
        },
        "lateral_movement": {
            "action": "lateral_movement",
            "mitre": "ATLAS: Lateral Movement",
            "description": "Tests whether the model assists in pivoting to other systems, accounts, or services via social engineering or token abuse.",
            "instance": LateralMovement(),
        },
        "evasion_techniques": {
            "action": "evasion_techniques",
            "mitre": "ATLAS: Defense Evasion",
            "description": "Tests whether the model can be deceived into bypassing its own safety measures, filters, or identity constraints.",
            "instance": EvasionTechniques(),
        },
        "context_manipulation": {
            "action": "context_manipulation",
            "mitre": "ATLAS: Impact (Context Manipulation)",
            "description": "Tests whether the model's behaviour was altered by manipulation of its context window, chat history, or trusted output components.",
            "instance": ContextManipulation(),
        },
        "impact": {
            "action": "impact",
            "mitre": "ATLAS: Impact",
            "description": "Tests whether the model can be used to cause denial of service, resource exhaustion, cost inflation, or real-world harm.",
            "instance": Impact(),
        },
    }

    return _mitre_registry


def get_probes():
    return get_owasp_probes()
