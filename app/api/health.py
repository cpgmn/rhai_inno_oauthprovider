"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    """Health check endpoint.

    Simple endpoint to verify the service is running.

    Returns:
        JSON response indicating service is healthy.
    """
    return {"status": "ok"}
