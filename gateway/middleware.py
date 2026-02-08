from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.client.mixins.tools import ClientToolsMixin
from fastmcp.telemetry import inject_trace_context
from fastapi import BackgroundTasks
from analyzer.filters import ScanFailure, dynamic_scan
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
    from gateway.urls import mcp
    propagated_meta = inject_trace_context(meta)

    if propagated_meta:
        traceparent = propagated_meta["fastmcp.traceparent"]
    
    # This has to be optimized
    session_response = await self.session.list_tools()
    session_tool_names = {tool.name for tool in session_response.tools}

    for proxy in mcp.proxies:
        proxy_tools = await proxy.list_tools()
        proxy_tool_names = {tool.name for tool in proxy_tools}

        if proxy_tool_names == session_tool_names:
            print(f"MATCH: {proxy.alias}")
            alias = proxy.alias
            break
        else:
            print(f"NO MATCH: {proxy.alias}")

    try:
        scan_result = dynamic_scan(logger, traceparent, "input", arguments, alias)
    except Exception as e:
        raise Exception(f"Input scan failed: {e}")

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

        try:
            scan_result = dynamic_scan(logger, traceparent, "output", out, alias)
        except Exception as e:
            raise Exception(f"Output scan failed: {e}")

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
