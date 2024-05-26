from fastapi import FastAPI
from src.settings import settings
from src.api.auth import router as auth_router
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="backend_lab",
    description="API Backend Lab",
    debug=settings.debug,
)


app.include_router(auth_router, prefix="/api")
