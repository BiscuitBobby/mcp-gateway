from pathlib import Path

from probes.base import StandardProbe


class EvasionTechniques(StandardProbe):
    """
    Tests whether the model can be deceived into bypassing its own safety
    measures, filters, or identity constraints.
    """

    name = "evasion_techniques"
    mitre_category = "ATLAS: Defense Evasion"
    record_type = "evasion_techniques_attack"
    prompts_file = Path(__file__).parent / "evasion_techniques_prompts.json"
