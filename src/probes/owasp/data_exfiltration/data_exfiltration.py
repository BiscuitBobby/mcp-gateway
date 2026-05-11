from pathlib import Path

from probes.base import StandardProbe


class DataExfiltration(StandardProbe):
    """
    Tests whether the model can be tricked into exfiltrating PII,
    conversation history, RAG contents, or API keys.
    """

    name = "data_exfiltration"
    owasp_category = "LLM06: Data Exfiltration"
    record_type = "data_exfiltration_attack"
    prompts_file = Path(__file__).parent / "data_exfiltration_prompts.json"
