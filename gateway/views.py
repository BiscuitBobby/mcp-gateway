from gateway.middleware import LoggingMiddleware, logger
from fastmcp.server import create_proxy
from async_lru import alru_cache
from fastmcp import FastMCP
import json

CONFIG_PATH = "config.json"

# monkey patch
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


@alru_cache(maxsize=1)
async def gateway_info(prox):
    data = {}

    for i in prox.proxies:
        data[i.alias] = {}

        try:
            data[i.alias]["name"] = f"{i}"
            data[i.alias]["tools"] = await i.list_tools()
            data[i.alias]["prompts"] = await i.list_prompts()
            data[i.alias]["resources"] = await i.list_resources()
        except:
            data[i.alias]["name"] = f"{i}"
            data[i.alias]["tools"] = []
            data[i.alias]["prompts"] = []
            data[i.alias]["resources"] = []

    return data
