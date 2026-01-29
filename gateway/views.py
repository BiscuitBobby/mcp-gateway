import json
from fastmcp import FastMCP
from async_lru import alru_cache
from fastmcp.server import create_proxy
from gateway.middleware import LoggingMiddleware, logger


# monkey patch 
FastMCP.alias = "default"

FastMCP.proxies = []

async def setup():
    mcp = FastMCP(name="GATEWAY")

    # config
    try:
        with open("config.json", "r") as f:
            config = json.load(f)

    except FileNotFoundError:
        logger.info("No config file found. Using default config.")
        config = {}
        with open("config.json", "w") as f:
            json.dump(config, f)

    # set up proxies
    for alias in config.keys():
        proxy = create_proxy({alias: config[alias]}, name=alias)
        proxy.alias = alias

        interceptor = LoggingMiddleware()
        proxy.add_middleware(interceptor)

        mcp.mount(
            proxy,
            namespace=alias
            )

        mcp.proxies.append(proxy)

    return mcp

@alru_cache(maxsize=1)
async def gateway_info(prox):
    data = dict()
    for i in prox.proxies:
        data[i.alias] = dict()
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
 
        #logger.info(str(data[i.alias]))

    #logger.info(40 * "-")

    return data
