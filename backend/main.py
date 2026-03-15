# backend/main.py
from dotenv import load_dotenv
load_dotenv()


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router
from auto_scanner import start_scheduler
from app.ai_router import router as ai_router


app = FastAPI(title="Shield Nexus Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")
app.include_router(ai_router, prefix="/api")



@app.on_event("startup")
def startup_event():
    start_scheduler()
