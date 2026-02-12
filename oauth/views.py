from gateway.models import gateway_info, load_config, mount_proxy, save_config
from oauth.utils import decode_token_endpoint, exchange_token, run_oauth_flow
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import Request, HTTPException, Query
from gateway.views import mcp
import requests
import json
import re

async def resolve_oauth(alias: str = Query(...)):
    if not re.match(r"^[a-zA-Z0-9_-]+$", alias):
        raise HTTPException(status_code=400, detail="Invalid alias")

    try:
        config_path = f"temp/{alias}.json"
        with open(config_path, "r") as f:
            cfg = json.load(f)

    except:
        raise HTTPException(status_code=400, detail="Alias config not found")

    resource_url = cfg.get("url")
    if not resource_url:
        raise HTTPException(status_code=400, detail="Missing resource URL in config")

    auth_header = ""
    base_redirect_uri = f"http://localhost:8000/callback/{alias}"
    client_name = "custom-client"

    try:
        auth_url, oauth_state = run_oauth_flow(
            resource_url,
            auth_header,
            base_redirect_uri,
            client_name,
        )

        with open(f"temp/{alias}_oauth_state.json", "w") as f:
            json.dump(oauth_state, f, indent=2)

        return RedirectResponse(url=auth_url)

    except requests.exceptions.HTTPError as e:
        raise HTTPException(status_code=400, detail=f"HTTP Error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")



async def oauth_callback(
    request: Request,
    alias: str,
    encoded_token_endpoint: str,
):
    # Validate alias
    if not re.match(r"^[a-zA-Z0-9_-]+$", alias):
        raise HTTPException(status_code=400, detail="Invalid alias")

    try:
        token_endpoint = decode_token_endpoint(encoded_token_endpoint)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token endpoint encoding")

    params = request.query_params

    if "code" in params:
        auth_code = params["code"]

        token_response = exchange_token(alias, auth_code, token_endpoint)

        access_token = token_response.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token returned")

        # Load original config
        try:
            config_path = f"temp/{alias}.json"

            with open(config_path, "r") as f:
                cfg = json.load(f)
        except:
            raise HTTPException(status_code=400, detail="Alias config not found")

        # Ensure headers exist
        if "headers" not in cfg:
            cfg["headers"] = {}

        # Replace Authorization header
        cfg["headers"]["Authorization"] = f"Bearer {access_token}"

        # Save updated config
        with open(config_path, "w") as f:
            json.dump(cfg, f, indent=2)

        # Mount proxy now that token exists
        for p in list(mcp.proxies):
            if p.alias == alias:
                mcp.unmount(alias)
                mcp.proxies.remove(p)

        await mount_proxy(mcp, alias, cfg)

        # Persist final config
        full_config = load_config()
        full_config[alias] = cfg
        save_config(full_config)

        gateway_info.cache_clear()

        return RedirectResponse(url="http://localhost:5173/agent-gateway")


    raise HTTPException(status_code=400, detail="Missing authorization code")
