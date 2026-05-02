# backend/main.py
from dotenv import load_dotenv
load_dotenv()

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router
from auto_scanner import start_scheduler
from app.ai_router import router as ai_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield


app = FastAPI(title="SentinelNexus", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ai_router registered first so its /api/ai/chat takes priority
app.include_router(ai_router, prefix="/api")
app.include_router(router, prefix="/api")
