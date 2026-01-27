import asyncio
from fastapi import APIRouter
from gateway.views import gateway_info, setup

mcp = asyncio.run(setup())
router = APIRouter()

@router.get("/inventory")
async def inventory():
    info = await gateway_info(mcp)
    return info
