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
from fastmcp.server.providers.proxy import FastMCPProxy
from fastmcp.server import create_proxy
from fastmcp import FastMCP
import json


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

        mcp.proxies.append(proxy)

    await gateway_info(mcp)
    return mcp


async def gateway_info(prox):
    data = dict()
    for i in prox.proxies:
        data[i.alias] = dict()
        data[i.alias]["name"] = f"{i}"
        data[i.alias]["tools"] = await i.list_tools()
        data[i.alias]["prompts"] = await i.list_prompts()
        data[i.alias]["resources"] = await i.list_resources()


    logger.info(str(data))
    logger.info(40 * "-")

    return data
