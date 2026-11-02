from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.ingest import router as ingest_router
from app.routers.dashboard import router as dashboard_router

app = FastAPI(
    title="Threat Intelligence Platform",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router)
app.include_router(dashboard_router)


@app.get("/")
def root():
    return {"status": "running"}