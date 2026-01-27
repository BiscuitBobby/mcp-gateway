from gateway.urls import router as gateway_router
from gateway.urls import mcp
from fastapi import FastAPI
import uvicorn


if __name__ == "__main__":
    # lifespan passed, path="/" since we mount at /mcp
    mcp_app = mcp.http_app(path="/")

    app = FastAPI(lifespan=mcp_app.lifespan)
    app.mount("/mcp", mcp_app)  # MCP endpoint at /mcp
    app.include_router(gateway_router)

    uvicorn.run(app, host="0.0.0.0", port=8000)
