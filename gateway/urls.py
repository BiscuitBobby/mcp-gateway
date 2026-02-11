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
    global mcp

    # update config
    config = load_config()
    if alias not in config:
        return {
            "status": "error",
            "message": f"Alias '{alias}' not found"
        }
    
    config.pop(alias)
    save_config(config)

    # invalidate cache
    gateway_info.cache_clear()
    
    # Find the mounted proxy
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
        # Disable the proxy first
        if hasattr(mounted_proxy, 'disable'):
            mounted_proxy.disable()
        
        # Remove from proxies list
        mcp.proxies = [p for p in mcp.proxies if p.alias != alias]
        
        # Remove from providers list
        if hasattr(mcp, 'providers'):
            mcp.providers = [p for p in mcp.providers if p != mounted_proxy]
        
        '''
        # Remove from _local_provider if it exists there
        if hasattr(mcp, '_local_provider') and hasattr(mcp._local_provider, 'servers'):
            mcp._local_provider.servers = [
                s for s in mcp._local_provider.servers if s != mounted_proxy
            ]
        '''
        
        # Clear any internal state
        if hasattr(mcp, '_docket'):
            # Force re-initialization of the docket on next request
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