"""reconforge HTTP API."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .service import ReconService

app = FastAPI(
    title="reconforge",
    version="1.0.0",
    summary="Aggregate authorized recon findings and score attack surface.",
)

_service: ReconService | None = None


def get_service() -> ReconService:
    global _service
    if _service is None:
        _service = ReconService()
    return _service


class AssessRequest(BaseModel):
    target: str = Field(min_length=1)


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/assess", tags=["recon"])
def assess(request: AssessRequest) -> dict:
    return get_service().assess(request.target)
