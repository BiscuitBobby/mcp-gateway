from fastapi import APIRouter
from .views import router as policy_router

router = APIRouter()

router.include_router(policy_router, prefix="/policies", tags=["policies"])
