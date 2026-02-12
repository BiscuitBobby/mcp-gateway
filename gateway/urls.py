from gateway.views import router as gateway_router
from fastapi import APIRouter

router = APIRouter()
router.include_router(gateway_router, prefix="", tags=["Gateway"])
