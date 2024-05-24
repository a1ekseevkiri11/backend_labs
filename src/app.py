from fastapi import FastAPI
from src.settings import settings
from src.api.auth import router as auth_router


app = FastAPI(
    title="backend_lab",
    description="API Backend Lab",
    debug=settings.debug,
)


app.include_router(auth_router, prefix="/api")
