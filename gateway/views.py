from gateway.middleware import logger


async def list_tools(proxy):
    tools = await proxy.get_tools()
    for i in tools:
        tool = await proxy.get_tool(i)
        print(tool.name)
    return tools

async def list_components(prox):
    logger.info(
    f'''{prox} ({prox.alias})
    "Tools:", {list(await prox.list_tools())}
    "Prompts:", {list(await prox.list_prompts())}
    "Resources:", {list(await prox.list_resources())}\n'''
    # "Resource Templates:", {list(await prox.list_resource_templates())}
    )

async def gateway_info(gateway):
    await list_components(gateway)
    logger.info(40*"-")
