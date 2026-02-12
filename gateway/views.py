from pydantic import BaseModel
from fastapi import APIRouter
import asyncio

from gateway.models import (
    gateway_info,
    load_config,
    mount_proxy,
    save_config,
    setup,
)

router = APIRouter()

# Initialize MCP once
mcp = asyncio.run(setup())


class ProxyCreate(BaseModel):
    alias: str
    config: dict


@router.get("/inventory")
async def inventory():
    return await gateway_info(mcp)


@router.post("/new")
async def add_proxy(payload: ProxyCreate):
    # Add or update a proxy at runtime.

    alias = payload.alias
    cfg = payload.config

    # Remove existing (update semantics)
    for p in list(mcp.proxies):
        if p.alias == alias:
            mcp.unmount(alias)
            mcp.proxies.remove(p)

    await mount_proxy(mcp, alias, cfg)

    # Persist
    config = load_config()
    config[alias] = cfg
    save_config(config)

    gateway_info.cache_clear()

    return {"status": "ok", "alias": alias}


@router.delete("/delete/{alias}")
async def remove_proxy(alias: str):
    config = load_config()
    if alias not in config:
        return {
            "status": "error",
            "message": f"Alias '{alias}' not found"
        }

    # Remove from config
    config.pop(alias)
    save_config(config)

    gateway_info.cache_clear()

    # Find mounted proxy
    mounted_proxy = None
    for proxy in mcp.proxies:
        if proxy.alias == alias:
            mounted_proxy = proxy
            break

    if not mounted_proxy:
        return {
            "status": "warning",
            "message": f"Proxy '{alias}' removed from config but was not mounted"
        }

    try:
        if hasattr(mounted_proxy, "disable"):
            mounted_proxy.disable()

        mcp.proxies = [p for p in mcp.proxies if p.alias != alias]

        if hasattr(mcp, "providers"):
            mcp.providers = [
                p for p in mcp.providers if p != mounted_proxy
            ]

        '''
        # Remove from _local_provider if it exists there
        if hasattr(mcp, '_local_provider') and hasattr(mcp._local_provider, 'servers'):
            mcp._local_provider.servers = [
                s for s in mcp._local_provider.servers if s != mounted_proxy
            ]
        '''

        if hasattr(mcp, "_docket"):
            mcp._docket = None

    except Exception as e:
        return {
            "status": "error",
            "message": f"Error unmounting proxy '{alias}': {str(e)}"
        }

    return {
        "status": "ok",
        "message": f"Proxy '{alias}' removed and unmounted successfully."
    }
