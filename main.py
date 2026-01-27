from gateway.views import setup
from fastapi import FastAPI
import uvicorn
import asyncio


if __name__ == "__main__":
    mcp = asyncio.run(setup())

    # lifespan passed, path="/" since we mount at /mcp
    mcp_app = mcp.http_app(path="/")
    app = FastAPI(lifespan=mcp_app.lifespan)
    app.mount("/mcp", mcp_app)  # MCP endpoint at /mcp

    uvicorn.run(app, host="0.0.0.0", port=8000)