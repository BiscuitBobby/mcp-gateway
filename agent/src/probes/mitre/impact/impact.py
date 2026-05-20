from pathlib import Path

from probes.base import StandardProbe


class Impact(StandardProbe):
    """
    Tests whether the model can be used to cause denial of service,
    resource exhaustion, cost inflation, or real-world harm.
    """

    name = "impact"
    mitre_category = "ATLAS: Impact"
    record_type = "impact_attack"
    prompts_file = Path(__file__).parent / "impact_prompts.json"
