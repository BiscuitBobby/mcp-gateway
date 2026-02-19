from config import settings # always import first for telemetry
from fastapi.responses import Response, StreamingResponse
from fastmcp.utilities.lifespan import combine_lifespans
from analyzer.urls import router as analyzer_router
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from gateway.urls import router as gateway_router
from policies.urls import router as policy_router
from sub_proxy.test import ServerRoutes, run_all
from oauth.urls import router as oauth_router
from contextlib import asynccontextmanager
from gateway.views import mcp
import uvicorn
import asyncio
import httpx

routes = ServerRoutes()
TIMEOUT = httpx.Timeout(None)
mcp_app = mcp.http_app(path="/")

@asynccontextmanager
async def app_lifespan(app):
    asyncio.create_task(run_all())
    yield

app = FastAPI(title=settings.app_name, lifespan=combine_lifespans(app_lifespan, mcp_app.lifespan))
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.api_route("/v1/{alias}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_alias(alias: str, request: Request):
    sd = routes.all()
    print(sd)
    if alias not in sd:
        raise HTTPException(status_code=404, detail="Alias not found")

    port = sd[alias]
    target_url = f"http://localhost:{port}/v1/{alias}/"

    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}

    client = httpx.AsyncClient(timeout=TIMEOUT)

    forwarded_request = client.build_request(
        request.method,
        target_url,
        headers=headers,
        content=await request.body(),
        params=request.query_params,
    )

    response = await client.send(forwarded_request, follow_redirects=False, stream=True)

    # Detect SSE or any streaming content-type and stream it back
    content_type = response.headers.get("content-type", "")
    is_streaming = (
        "text/event-stream" in content_type
        or "application/octet-stream" in content_type
        or response.headers.get("transfer-encoding", "").lower() == "chunked"
    )

    if is_streaming:
        async def stream_generator():
            try:
                async for chunk in response.aiter_bytes():
                    yield chunk
            finally:
                await response.aclose()
                await client.aclose()

        return StreamingResponse(
            stream_generator(),
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items()
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")
            },
            media_type=content_type,
        )

    # Non-streaming: buffer the response normally
    try:
        content = await response.aread()
        return Response(
            content=content,
            status_code=response.status_code,
            headers=dict(response.headers),
        )
    finally:
        await response.aclose()
        await client.aclose()


app.mount("/mcp", mcp_app)  # MCP endpoint at /mcp
app.include_router(gateway_router)
app.include_router(analyzer_router)
app.include_router(policy_router)
app.include_router(oauth_router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
