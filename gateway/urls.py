from gateway.views import gateway_info, load_config, mount_proxy, save_config, setup
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import asyncio


mcp = asyncio.run(setup())
router = APIRouter()


class ProxyCreate(BaseModel):
    alias: str
    config: dict


@router.get("/inventory")
async def inventory():
    return await gateway_info(mcp)


@router.post("/new")
async def add_proxy(payload: ProxyCreate):
    """
    Add or update a proxy at runtime.
    """

    alias = payload.alias
    cfg = payload.config

    # Remove existing if present (update semantics)
    for p in list(mcp.proxies):
        if p.alias == alias:
            mcp.unmount(alias)
            mcp.proxies.remove(p)

    await mount_proxy(mcp, alias, cfg)

    # persist
    config = load_config()
    config[alias] = cfg
    save_config(config)

    # invalidate cache
    gateway_info.cache_clear()

    return {"status": "ok", "alias": alias}


@router.delete("/delete/{alias}")
async def remove_proxy(alias: str):
    """
    Remove proxy by alias.
    """

    found = False

    for p in list(mcp.proxies):
        if p.alias == alias:
            mcp.unmount(alias)
            mcp.proxies.remove(p)
            found = True
            break

    if not found:
        raise HTTPException(status_code=404, detail="Proxy not found")

    # update config
    config = load_config()
    config.pop(alias, None)
    save_config(config)

    # invalidate cache
    gateway_info.cache_clear()

    return {"status": "removed", "alias": alias}
