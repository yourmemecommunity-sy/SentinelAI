"""policy-engine service skeleton.

NOT IMPLEMENTED YET (see docs/architecture/roadmap.md). Until it is, /ready reports 503 so the
gateway treats this dependency as unavailable and FAILS CLOSED rather than bypassing it.
"""
from fastapi import FastAPI, Response

app = FastAPI(title="sentinel-policy-engine", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "alive", "service": "policy-engine"}


@app.get("/ready")
def ready(response: Response) -> dict[str, str]:
    response.status_code = 503
    return {"status": "not_ready", "reason": "not implemented"}
