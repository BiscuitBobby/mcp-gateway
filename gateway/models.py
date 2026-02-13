from gateway.middleware import LoggingMiddleware, logger
from fastmcp.server import create_proxy
from async_lru import alru_cache
from fastmcp import FastMCP
import asyncio
import json

CONFIG_PATH = "config.json"

# Monkey patch
FastMCP.alias = "default"
FastMCP.proxies = []


def load_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.info("No config file found. Using default config.")
        with open(CONFIG_PATH, "w") as f:
            json.dump({}, f)
        return {}


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


async def mount_proxy(mcp: FastMCP, alias: str, cfg: dict):
    proxy = create_proxy({alias: cfg}, name=alias)
    proxy.alias = alias

    interceptor = LoggingMiddleware(alias)
    proxy.add_middleware(interceptor)

    mcp.mount(proxy, namespace=alias)
    mcp.proxies.append(proxy)

    return proxy


async def setup():
    mcp = FastMCP(name="GATEWAY")
    config = load_config()

    for alias, cfg in config.items():
        await mount_proxy(mcp, alias, cfg)

    return mcp

@alru_cache(maxsize=128)
async def proxy_info(proxy):
    try:
        tools, prompts, resources = await asyncio.gather(
            proxy.list_tools(),
            proxy.list_prompts(),
            proxy.list_resources(),
        )

        return {
            "name": str(proxy),
            "tools": tools,
            "prompts": prompts,
            "resources": resources,
        }

    except Exception:
        return {
            "name": str(proxy),
            "tools": [],
            "prompts": [],
            "resources": [],
        }


@alru_cache(maxsize=1)
async def gateway_info(prox):
    proxies = list(prox.proxies)

    results = await asyncio.gather(
        *(proxy_info(p) for p in proxies),
        return_exceptions=True
    )

    data = {}
    for p, result in zip(proxies, results):
        if isinstance(result, Exception):
            data[p.alias] = {
                "name": str(p),
                "tools": [],
                "prompts": [],
                "resources": [],
            }
        else:
            data[p.alias] = result

    return data
