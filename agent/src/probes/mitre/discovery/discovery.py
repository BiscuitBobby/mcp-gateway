from pathlib import Path

from probes.base import StandardProbe


class Discovery(StandardProbe):
    """
    Tests whether the model reveals information about its own architecture,
    configuration, capabilities, or the AI system it belongs to.
    """

    name = "discovery"
    mitre_category = "ATLAS: Discovery"
    record_type = "discovery_attack"
    prompts_file = Path(__file__).parent / "discovery_prompts.json"
