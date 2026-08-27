from fastapi import FastAPI

from contracts.models import CONTRACT_VERSION

app = FastAPI(title="SENTINEL API", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "contract_version": CONTRACT_VERSION}
