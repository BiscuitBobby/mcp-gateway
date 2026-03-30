from probes.prompt_injection.generate_prompts import main as gen_prompt_injection
from probes.sensitive_information_disclosure.generate_prompts import (
    main as gen_sensitive,
)

from probes.data_exfiltration.generate_prompts import main as gen_data_exfil
from probes.excessive_agency.generate_prompts import main as gen_excessive_agency
from probes.improper_output_handling.generate_prompts import main as gen_improper_output
from probes.misinformation.generate_prompts import main as gen_misinformation

import logging

logger = logging.getLogger(__name__)

GENERATORS = [
    ("prompt_injection", gen_prompt_injection),
    ("sensitive_information_disclosure", gen_sensitive),
    ("data_exfiltration", gen_data_exfil),
    ("excessive_agency", gen_excessive_agency),
    ("improper_output_handling", gen_improper_output),
    ("misinformation", gen_misinformation),
]


def generate_all(app_profile=None, model_profile=None):
    summary = {}

    for name, main in GENERATORS:
        logger.info("[generate_all] Generating payloads for: %s", name)
        try:
            result = main(app_profile=app_profile, model_profile=model_profile)
            summary[name] = {"status": "ok", "count": len(result) if result else 0}
        except Exception as exc:
            logger.exception("[generate_all] %s failed: %s", name, exc)
            summary[name] = {"status": "error", "error": str(exc)}

    return summary
