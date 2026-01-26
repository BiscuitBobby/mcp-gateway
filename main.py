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

from gateway.middleware import LoggingMiddleware
from fastmcp.server import create_proxy
from gateway.views import gateway_info
from fastmcp import FastMCP
import asyncio
import json


# monkey patch to add secondary server name
FastMCP.alias = "default"

# aggregate proxy
mcp = FastMCP(name="GATEWAY")

# mcp config
with open("config.json", "r") as f:
    config = json.load(f)

async def setup():
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


if __name__ == "__main__":
    asyncio.run(setup())

    # IMPORTANT: run AFTER asyncio exits
    mcp.run(transport="streamable-http", port=8000)
