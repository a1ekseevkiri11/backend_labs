from fastapi import FastAPI
from contextlib import asynccontextmanager
import pytz

from src.settings import settings
from src.auth import routers as auth_routers
from src.role_policy import routers as role_policy_routers



@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="backend_lab",
    description="API Backend Lab",
    debug=settings.debug,
)


app.include_router(auth_routers.auth_router, prefix="/api")
app.include_router(auth_routers.user_router, prefix="/api")
app.include_router(role_policy_routers.role_router, prefix="/api")
app.include_router(role_policy_routers.permission_router, prefix="/api")


