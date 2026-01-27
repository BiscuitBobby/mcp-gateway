from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

resource = Resource.create({
    "service.name": "mcp-gateway"
})

# Configure the SDK with OTLP exporter
provider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)

from gateway.middleware import LoggingMiddleware, logger
from fastmcp.server import create_proxy
from fastmcp import FastMCP
import json


# monkey patch to add secondary server name
FastMCP.alias = "default"

mcp = FastMCP(name="GATEWAY")


async def setup():
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
        proxy = create_proxy({alias: config[alias]})
        proxy.alias = alias

        interceptor = LoggingMiddleware()
        interceptor.key = alias

        await gateway_info(proxy)

        proxy.add_middleware(interceptor)

        mcp.mount(
            proxy,
            namespace=alias
            )

    await gateway_info(mcp)
    return mcp


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
