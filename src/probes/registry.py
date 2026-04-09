from dotenv import load_dotenv

load_dotenv()

from probes.prompt_injection.prompt_injection import PromptInjectionProbe
from probes.sensitive_information_disclosure.sensitive_information_disclosure import (
    SensitiveInformationDisclosureProbe,
)
from probes.misinformation.misinformation import MisinformationProbe
from probes.improper_output_handling.improper_output_handling import (
    ImproperOutputHandlingProbe,
)
from probes.excessive_agency.excessive_agency import ExcessiveAgencyProbe
from probes.rag_poisoning.rag_poisoning import RagPoisoningProbe
from probes.tool_misuse.tool_misuse import ToolMisuseProbe

_registry = None


def get_probes():
    global _registry
    if _registry is not None:
        return _registry

    _registry = {
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
            "owasp": "LLM06: Sensitive Information Disclosure",
            "description": "Tests whether the model can be tricked into exfiltrating PII, conversation history, RAG contents, or API keys.",
            "prompts_file": "data_exfiltration_prompts.json",
            "instance": None,  # not yet implemented
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
            "owasp": "LLM02: Insecure Output Handling",
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
            "prompts_file": "rag_poisoning_payloads.json",
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

    return _registry
