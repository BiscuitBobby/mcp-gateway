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

from fastapi.middleware.cors import CORSMiddleware
from analyzer.urls import router as analyzer_router
from gateway.urls import router as gateway_router
from policies.urls import router as policy_router
from oauth.urls import router as oauth_router
from gateway.views import mcp
from fastapi import FastAPI
import uvicorn

# lifespan passed, path="/" since we mount at /mcp
mcp_app = mcp.http_app(path="/")

app = FastAPI(lifespan=mcp_app.lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local host port for Jaeger or ["*"] for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/mcp", mcp_app)  # MCP endpoint at /mcp
app.include_router(gateway_router)
app.include_router(analyzer_router)
app.include_router(policy_router)
app.include_router(oauth_router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
