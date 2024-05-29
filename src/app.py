from fastapi import FastAPI
from contextlib import asynccontextmanager

from src.settings import settings
from src.auth.routers import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="backend_lab",
    description="API Backend Lab",
    debug=settings.debug,
)


app.include_router(auth_router, prefix="/api")



