from fastmcp.server.middleware import Middleware, MiddlewareContext
from analyzer.filters import ScanFailure, dynamic_scan
from fastmcp.telemetry import inject_trace_context
import logging


logger = logging.getLogger("mcpLogger")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.FileHandler("mcp.log"))


class LoggingMiddleware(Middleware):
    def __init__(self, name: str = "default"):
        super().__init__()
        self.name = name

    async def on_message(self, context: MiddlewareContext, call_next):
        if context.method == "tools/call":
            context.message.meta = inject_trace_context(context.message.meta)


        result = await call_next(context)

        if context.method != "tools/call":
            logger.info("response: %s", result)
            return result

        # ---- tools/call path ----

        propagated_meta = inject_trace_context(result.meta)
        traceparent = propagated_meta["fastmcp.traceparent"]
        print(self.name, context.method, traceparent)
        try:
            dynamic_scan(
                logger,
                traceparent,
                "input",
                result.content,
                self.name,
            )
        except Exception as e:
            raise Exception(f"Input scan failed: {e}") from e

        out = {
            "content": result.content,
            "structured_content": result.structured_content,
            "meta": result.meta,
        }

        logger.info("response: %s", result)

        try:
            scan_result = dynamic_scan(
                logger,
                traceparent,
                "output",
                out,
                self.name,
            )
        except Exception as e:
            raise Exception(f"Output scan failed: {e}") from e

        if isinstance(scan_result, ScanFailure):
            raise Exception(f"Output scan failed: {scan_result.error}")

        logger.info("\n")
        return result