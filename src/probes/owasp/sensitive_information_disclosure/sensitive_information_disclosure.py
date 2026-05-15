from pathlib import Path

from probes.base import StandardProbe


class SensitiveInformationDisclosure(StandardProbe):
    """
    Tests whether the model leaks system prompts, credentials, or sensitive
    data through benign-sounding questions.
    """

    name = "sensitive_information_disclosure"
    owasp_category = "LLM02: Sensitive Information Disclosure"
    record_type = "sensitive_information_disclosure_attack"
    prompts_file = Path(__file__).parent / "sensitive_info_prompts.json"
