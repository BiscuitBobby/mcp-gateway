from fastapi import APIRouter
from analyzer.views import status

router = APIRouter()

@router.get("/status")
async def status_endpoint(id: str):
    return status(id)
