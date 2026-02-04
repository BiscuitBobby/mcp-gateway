from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.client.mixins.tools import ClientToolsMixin
from fastmcp.telemetry import inject_trace_context
from fastapi import BackgroundTasks
from analyzer.filters import ScanFailure, dynamic_scan
from analyzer.views import run_scan
import logging


logger = logging.getLogger("mcpLogger")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("mcp.log")
logger.addHandler(file_handler)

background_tasks = BackgroundTasks()

'''
need to watch out for changes in call_tool_mcp since I've monkey patched an internal function
'''

# Save original
_original_call_tool_mcp = ClientToolsMixin.call_tool_mcp


async def patched_call_tool_mcp(
    self,
    name,
    arguments,
    progress_handler=None,
    timeout=None,
    meta=None,
):
    propagated_meta = inject_trace_context(meta)

    if propagated_meta:
        traceparent = propagated_meta["fastmcp.traceparent"]

        run_scan(logger, traceparent, "input", arguments)

        scan_result = dynamic_scan(logger, traceparent, "input", arguments)
        if isinstance(scan_result, ScanFailure):
            raise Exception(f"Input scan failed: {scan_result.error}")

    out = await _original_call_tool_mcp(
        self,
        name=name,
        arguments=arguments,
        progress_handler=progress_handler,
        timeout=timeout,
        meta=propagated_meta,
    )

    if propagated_meta:
        traceparent = propagated_meta["fastmcp.traceparent"]

        run_scan(logger, traceparent, "output", out)

        scan_result = dynamic_scan(logger, traceparent, "output", out)
        if isinstance(scan_result, ScanFailure):
            raise Exception(f"Output scan failed: {scan_result.error}")

    return out


# Monkey patch
ClientToolsMixin.call_tool_mcp = patched_call_tool_mcp


class LoggingMiddleware(Middleware):
    def __init__(self):
        super().__init__()

    async def on_message(self, context: MiddlewareContext, call_next):
        logger.info(f"request: {context.__dict__}")

        result = await call_next(context)

        if context.method == "tools/call":
            out = {
                "content": result.content,
                "structured_content": result.structured_content,
                "meta": result.meta
            }
            
            logger.info(f"response: {out}")
        else:
            logger.info(f"response: {result}")

        logger.info("\n")
        return result
