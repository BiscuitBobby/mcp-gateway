from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from pydantic_settings import BaseSettings, SettingsConfigDict
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry import trace
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "mcp-gateway"
    debug: bool = False

    otl_exporter_url: str = "http://localhost:4317"
    frontend_url: str = "http://localhost:5173"
    temp_dir: str = "temp"
    host: str = "http://localhost:8000"
    # database_url: str


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


resource = Resource.create({
    "service.name": settings.app_name
})

# Configure the SDK with OTLP exporter
provider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otl_exporter_url))
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)