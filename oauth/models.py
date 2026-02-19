from pydantic import BaseModel
from config import settings
from typing import Optional
import json


class OAuthState(BaseModel):
    code_verifier: str
    client_id: str
    redirect_uri: str
    client_secret: Optional[str] = None


def load_oauth_state(alias) -> OAuthState:
    try:
        with open(f"{settings.temp_dir}/{alias}_oauth_state.json", "r") as f:
            data = json.load(f)
            return OAuthState(**data)
    except FileNotFoundError:
        raise FileNotFoundError("oauth_state.json not found. Run OAuth registration first.")
    except KeyError as e:
        raise KeyError(f"Missing required field in oauth_state.json: {e}")
