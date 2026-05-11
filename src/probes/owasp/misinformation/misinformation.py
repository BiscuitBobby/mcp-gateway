from pathlib import Path

from probes.base import StandardProbe


class Misinformation(StandardProbe):
    """
    Tests whether the model can be manipulated into confidently asserting
    false facts, fabricated citations, or invented statistics.
    """

    name = "misinformation"
    owasp_category = "LLM04: Misinformation"
    record_type = "misinformation_attack"
    prompts_file = Path(__file__).parent / "misinformation_prompts.json"
