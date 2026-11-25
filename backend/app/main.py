import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router

app = FastAPI(
    title="PhishGuard AI | Phishing & Business Email Compromise Investigative System",
    version="1.0.0",
    description="Dual ML + LangGraph Multi-Agent + RAG Cybersecurity Investigation Copilot",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Status"])
def root():
    return {
        "service": "PhishGuard AI API",
        "status": "online",
        "docs": "/docs",
        "health": "/api/health",
    }


app.include_router(router)