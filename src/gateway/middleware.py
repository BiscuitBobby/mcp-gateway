from fastmcp.server.middleware import Middleware, MiddlewareContext
from src.analyzer.filters import ScanFailure, dynamic_scan
from fastmcp.telemetry import inject_trace_context
import logging


logger = logging.getLogger("mcpLogger")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.FileHandler("mcp.log"))


class LoggingMiddleware(Middleware):
    def __init__(self, name: str = "default"):
        super().__init__()
        self.name = name
        print(f"[LoggingMiddleware] Initialized for: {self.name}")

    async def on_message(self, context: MiddlewareContext, call_next):
        print(f"[LoggingMiddleware] {self.name} - on_message called, method: {context.method}")
        
        if context.method == "tools/call":
            context.message.meta = inject_trace_context(context.message.meta)
            print(f"[LoggingMiddleware] {self.name} - Injected trace context for tools/call")

        result = await call_next(context)
        print(f"[LoggingMiddleware] {self.name} - Received result from call_next")

        if context.method != "tools/call":
            logger.info("response: %s", result)
            print(f"[LoggingMiddleware] {self.name} - Non-tools/call method, returning result")
            return result

        # ---- tools/call path ----
        print(f"[LoggingMiddleware] {self.name} - Processing tools/call path")

        propagated_meta = inject_trace_context(result.meta)
        traceparent = propagated_meta.get("fastmcp.traceparent")
        
        if not traceparent:
            logger.warning("No traceparent found in meta, skipping dynamic scan")
            print(f"[LoggingMiddleware] {self.name} - WARNING: No traceparent found, skipping scan")
            return result
            
        print(f"[LoggingMiddleware] {self.name} - traceparent: {traceparent}")
        print(self.name, context.method, traceparent)
        
        try:
            print(f"[LoggingMiddleware] {self.name} - Running input scan")
            dynamic_scan(
                logger,
                traceparent,
                "input",
                result.content,
                self.name,
            )
            print(f"[LoggingMiddleware] {self.name} - Input scan completed")
        except Exception as e:
            print(f"[LoggingMiddleware] {self.name} - Input scan FAILED: {e}")
            raise Exception(f"Input scan failed: {e}") from e

        out = {
            "content": result.content,
            "structured_content": result.structured_content,
            "meta": result.meta,
        }

        logger.info("response: %s", result)

        try:
            print(f"[LoggingMiddleware] {self.name} - Running output scan")
            scan_result = dynamic_scan(
                logger,
                traceparent,
                "output",
                out,
                self.name,
            )
            print(f"[LoggingMiddleware] {self.name} - Output scan completed")
        except Exception as e:
            print(f"[LoggingMiddleware] {self.name} - Output scan FAILED: {e}")
            raise Exception(f"Output scan failed: {e}") from e

        if isinstance(scan_result, ScanFailure):
            print(f"[LoggingMiddleware] {self.name} - Output scan returned ScanFailure: {scan_result.error}")
            raise Exception(f"Output scan failed: {scan_result.error}")

        logger.info("\n")
        print(f"[LoggingMiddleware] {self.name} - Middleware processing complete, returning result")
        return result
