from pathlib import Path

from probes.base import StandardProbe


class ExcessiveAgency(StandardProbe):
    """
    Tests whether the model takes unauthorised real-world actions such as
    sending emails, modifying accounts, or executing destructive operations.
    """

    name = "excessive_agency"
    owasp_category = "LLM08: Excessive Agency"
    record_type = "excessive_agency_attack"
    prompts_file = Path(__file__).parent / "excessive_agency_prompts.json"
