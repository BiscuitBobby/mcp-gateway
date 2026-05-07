from probes.owasp.prompt_injection.generate_prompts import main as gen_prompt_injection
from probes.owasp.sensitive_information_disclosure.generate_prompts import main as gen_sensitive
from probes.owasp.data_exfiltration.generate_prompts import main as gen_data_exfil
from probes.owasp.excessive_agency.generate_prompts import main as gen_excessive_agency
from probes.owasp.improper_output_handling.generate_prompts import main as gen_improper_output
from probes.owasp.misinformation.generate_prompts import main as gen_misinformation
from probes.owasp.rag_poisoning.generate_prompts import main as gen_rag_poisoning
from probes.owasp.rag_poisoning.generate_documents import main as gen_rag_docs
from probes.owasp.tool_misuse.generate_prompts import main as gen_tool_misuse
from probes.mitre.ai_attack_staging.generate_prompts import main as gen_attack_staging
from probes.mitre.collection.generate_prompts import main as gen_collection
from probes.mitre.credential_extraction.generate_prompts import main as gen_credential_extraction
from probes.mitre.discovery.generate_prompts import main as gen_discovery
from probes.mitre.evasion_techniques.generate_prompts import main as gen_evasion_techniques
from probes.mitre.impact.generate_prompts import main as gen_impact
from probes.mitre.lateral_movement.generate_prompts import main as gen_lateral_movement
from probes.mitre.reconnaissance.generate_prompts import main as gen_reconnaissance
from probes.mitre.user_execution.generate_prompts import main as gen_user_execution

import logging

logger = logging.getLogger(__name__)

GENERATORS = [
    ("prompt_injection", gen_prompt_injection),
    ("sensitive_information_disclosure", gen_sensitive),
    ("data_exfiltration", gen_data_exfil),
    ("excessive_agency", gen_excessive_agency),
    ("improper_output_handling", gen_improper_output),
    ("misinformation", gen_misinformation),
    ("rag_poisoning", gen_rag_poisoning),
    ("rag_poisoning_docs", gen_rag_docs),
    ("tool_misuse", gen_tool_misuse),
    ("attack_staging", gen_attack_staging),
    ("collection", gen_collection),
    ("credential_extraction", gen_credential_extraction),
    ("discovery", gen_discovery),
    ("evasion_techniques", gen_evasion_techniques),
    ("impact", gen_impact),
    ("lateral_movement", gen_lateral_movement),
    ("reconnaissance", gen_reconnaissance),
    ("user_execution", gen_user_execution),
]


def generate_all(app_profile=None, interface_map=None, goal=None, vulnerabilities=None):
    summary = {}

    for name, main in GENERATORS:
        logger.info("[generate_all] Generating payloads for: %s", name)
        try:
            result = main(
                app_profile=app_profile,
                interface_map=interface_map,
                goal=goal,
                vulnerabilities=vulnerabilities,
            )
            summary[name] = {"status": "ok", "count": len(result) if result else 0}
        except Exception as exc:
            logger.exception("[generate_all] %s failed: %s", name, exc)
            summary[name] = {"status": "error", "error": str(exc)}

    return summary
