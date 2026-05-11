from pathlib import Path

from probes.base import StandardProbe


class ImproperOutputHandling(StandardProbe):
    """
    Tests whether the model produces dangerous structured output — injected HTML,
    forged tool calls, malformed JSON with privilege fields.
    """

    name = "improper_output_handling"
    owasp_category = "LLM05: Improper Output Handling"
    record_type = "improper_output_handling_attack"
    prompts_file = Path(__file__).parent / "improper_output_handling_prompts.json"
