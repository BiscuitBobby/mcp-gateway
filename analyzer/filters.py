from typing import Literal
from analyzer.models import (
    store,
    Report,
    get_scan_id,
)
from typing import Union
from dataclasses import dataclass
from langchain_google_genai import ChatGoogleGenerativeAI
import getpass
import os

from policies.views import GLOBAL_POLICIES, get_policies, load_json

if "GOOGLE_API_KEY" not in os.environ:
    os.environ["GOOGLE_API_KEY"] = getpass.getpass("Enter your Google AI API key: ")

model = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    temperature=1.0,  # Gemini 3.0+ defaults to 1.0
    max_tokens=None,
    timeout=None,
    max_retries=2,
)

model_with_structure = model.with_structured_output(Report)

# --------------------
# scanning logic
# --------------------
@dataclass
class ScanSuccess:
    result: dict

@dataclass
class ScanFailure:
    error: str

def dynamic_scan(
    logger, 
    traceparent: str, 
    text_type: Literal["input", "output"], 
    text,
    server_alias
) -> Union[ScanSuccess, ScanFailure]:
    scan_id = get_scan_id(traceparent)
    text = str(text)
    policies = get_policies(server_alias)["policies"]

    selected_policies = {
        policy: load_json(GLOBAL_POLICIES, {})[policy]
        for policy in policies
    }

    messages = [
        (
            "system",
            f"You are an auditing assistant that checks for attacks such as this:\n{selected_policies}",
        ),
        ("human", text),
    ]
    
    try:
        ai_msg = model_with_structure.invoke(messages)
        store(scan_id, text_type, text, {text_type: ai_msg.model_dump()})
        logger.info(f"scan:{ai_msg}")
        
        if ai_msg.threat:
            return ScanFailure(error="Attack detected")
        
        return ScanSuccess(result=ai_msg)
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return ScanFailure(error=str(e))