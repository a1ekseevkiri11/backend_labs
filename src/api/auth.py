from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response,
    status,
    HTTPException,
)
from fastapi.security import (
    OAuth2PasswordRequestForm,
    OAuth2PasswordBearer,
)
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated


from src.database import databaseHandler
from src.services.auth import services as auth_services
from src.models import auth as auth_model


router = APIRouter(tags=["Auth"], prefix="/auth")

oauth_schema = OAuth2PasswordBearer(tokenUrl="/api/auth/login/")


@router.post("/login/", response_model=auth_model.Token)
async def login(
        user_data: OAuth2PasswordRequestForm = Depends(),
        session: AsyncSession = Depends(databaseHandler.get_session)
):
    try:
        user_data = auth_model.LoginRequest(
            username=user_data.username,
            password=user_data.password
        )
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_423_UNPROCESSABLE_ENTITY_FORBIDDEN, detail=f"{ex}")
    return await auth_services.login(
        user_data=user_data,
        session=session
    )


@router.post(
    "/register/",
    response_model=auth_model.OutputUser,
    status_code=status.HTTP_201_CREATED
)
async def register(
        user_data: auth_model.RegisterRequest,
        session: AsyncSession = Depends(databaseHandler.get_session)
):
    return await auth_services.register(
        user_data=user_data,
        session=session
    )


async def valid_token(
        token: str = Depends(oauth_schema),
        session: AsyncSession = Depends(databaseHandler.get_session)
):
    return await auth_services.validate_token(
        token=token,
        session=session,
    )


@router.get("/tokens/")
async def tokens(
        token: auth_model.User = Depends(valid_token),
):
    return token




@router.get("/me/")
async def me(
        token: auth_model.User = Depends(valid_token),
        session: AsyncSession = Depends(databaseHandler.get_session),
):
    return await auth_services.current_user(
        session=session,
        token=token,
    )


@router.post("/out/")
async def logout(
        token: auth_model.User = Depends(valid_token),
        session: AsyncSession = Depends(databaseHandler.get_session)
):
    return await auth_services.logout(
        token=token,
        session=session,
    )


@router.post("/out_all/")
async def logout_all(
        token: auth_model.User = Depends(valid_token),
        session: AsyncSession = Depends(databaseHandler.get_session)
):
    return await auth_services.logout(
        token=token,
        session=session,
    )

