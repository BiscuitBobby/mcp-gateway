from fastmcp.server.middleware import Middleware, MiddlewareContext
import fastmcp
import logging


logger = logging.getLogger("mcpLogger")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("mcp.log")
logger.addHandler(file_handler)


class LoggingMiddleware(Middleware):
    def __init__(self):
        super().__init__()
        self.key = "default"

    async def on_message(self, context: MiddlewareContext, call_next):
        result = await call_next(context)

        logger.info(f"{self.key}")
        logger.info(f"request: {context.__dict__}")

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
