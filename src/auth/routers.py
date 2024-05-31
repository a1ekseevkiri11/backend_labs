from fastapi import (
    APIRouter,
    Depends,
    Response,
    Request,
    status,
    HTTPException,
)
from fastapi.security import (
    OAuth2PasswordRequestForm,
    OAuth2PasswordBearer,
)
from sqlalchemy.ext.asyncio import AsyncSession


from src.auth import services as auth_services
from src.auth import schemas as auth_schemas
from src import exceptions
from src.settings import settings


router = APIRouter(tags=["Auth"], prefix="/auth")


@router.post(
    "/login/",
    response_model=auth_schemas.Token)
async def login(
    response: Response,
    user_data: OAuth2PasswordRequestForm = Depends(),
):
    try:
        user_data = auth_schemas.LoginRequest(
            username=user_data.username,
            password=user_data.password
        )

    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_423_UNPROCESSABLE_ENTITY_FORBIDDEN, detail=f"{ex}")

    user = await auth_services.AuthService.login(user_data=user_data)

    if not user:
        raise exceptions.InvalidCredentialsException

    token = await auth_services.JWTServices.create(user.id)
    response.set_cookie(
        'access_token',
        token.access_token,
        max_age=settings.auth_jwt.access_token_expire_minutes,
        httponly=True
    )
    return token


@router.post(
    "/register/",
    response_model=auth_schemas.UserResponse,
    status_code=status.HTTP_201_CREATED
)
async def register(
        user_data: auth_schemas.RegisterRequest,
):
    return await auth_services.UserService.add(
        user_data=user_data
    )


@router.get("/tokens/")
async def tokens(
        user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await auth_services.JWTServices.get_all(user_id=user.id)


@router.get("/me/", response_model=auth_schemas.UserResponse)
async def me(
        user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return user


@router.post("/out/")
async def logout(
        request: Request,
        response: Response,
        user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.JWTServices.delete(token=user.token)
    response.delete_cookie('access_token')
    return {"message": "Logged out successfully"}


@router.post("/out_all/")
async def logout_all(
        response: Response,
        user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    response.delete_cookie('access_token')
    await auth_services.JWTServices.delete_all(user_id=user.id)
    return {"message": "ALL Logged out successfully"}

