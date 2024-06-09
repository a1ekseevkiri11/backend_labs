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
)


from src.auth import services as auth_services
from src.auth import schemas as auth_schemas
from src.role_policy import schemas as role_policy_schemas
from src import exceptions
from src.settings import settings
from src.log import schemas as log_schemas


auth_router = APIRouter(tags=["Auth"], prefix="/auth")


@auth_router.post(
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


@auth_router.post(
    "/otp/",
    response_model=auth_schemas.LoginResponse)
async def otp_generate(
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

    await auth_services.OTPServices.generate(user_data=user)
    return {
        "user": user,
        "message": f"OTP send in your email: {user.email}"
    }


@auth_router.post(
    "/otp/{user_id}/",
    response_model=auth_schemas.Token
)
async def otp_check(
        response: Response,
        user_id: int,
        code: int
):
    otp_data = auth_schemas.OTPRequest(
        user_id=user_id,
        code=code
    )
    if not await auth_services.OTPServices.is_valid(
        otp_data=otp_data,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Code incorrect",
        )

    token = await auth_services.JWTServices.create(otp_data.user_id)
    response.set_cookie(
        'access_token',
        token.access_token,
        max_age=settings.auth_jwt.access_token_expire_minutes,
        httponly=True
    )

    return token


@auth_router.post(
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


@auth_router.get("/tokens/")
async def tokens(
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await auth_services.JWTServices.get_all(current_user_id=current_user.id)


@auth_router.get("/me/", response_model=auth_schemas.UserResponse)
async def me(
        user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return user


@auth_router.post("/out/")
async def logout(
        request: Request,
        response: Response,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.JWTServices.delete(token=current_user.token)
    response.delete_cookie('access_token')
    return {"message": "Logged out successfully"}


@auth_router.post("/out_all/")
async def logout_all(
        response: Response,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    response.delete_cookie('access_token')
    await auth_services.JWTServices.delete_all(current_user_id=current_user.id)
    return {"message": "ALL Logged out successfully"}


user_router = APIRouter(tags=["User"], prefix="/ref/user")


@user_router.get(
    "/",
    response_model=list[auth_schemas.UserResponse]
)
async def user_get_all(
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.UserService.check_permission(
        permission_title="get-list-users",
        user_id=current_user.id
    )

    return await auth_services.UserService.get_all()


@user_router.get(
    "/{user_id}/",
    response_model=auth_schemas.UserResponse
)
async def user_get(
        user_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.UserService.check_permission(
        permission_title="read-users",
        user_id=current_user.id,
        request_user_id=user_id
    )

    return await auth_services.UserService.get(user_id=user_id)


@user_router.post(
    "/",
    response_model=auth_schemas.UserResponse
)
async def user_add(
        user_data: auth_schemas.RegisterRequest,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.UserService.check_permission(
        permission_title="create-users",
        user_id=current_user.id,
    )
    return await auth_services.UserService.add(
        user_data=user_data,
        current_user_id=current_user.id
    )


@user_router.put(
    "/{user_id}/",
    response_model=auth_schemas.UserResponse
)
async def user_update(
        user_id: int,
        user_data: auth_schemas.UserRequest,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user),
):
    await auth_services.UserService.check_permission(
        permission_title="update-users",
        user_id=current_user.id,
        request_user_id=user_id
    )
    return await auth_services.UserService.update(
        current_user_id=current_user.id,
        user_id=user_id,
        user_data=user_data,
    )


@user_router.delete(
    "/{user_id}/",
)
async def user_delete(
        user_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user),
):
    await auth_services.UserService.check_permission(
        permission_title="delete-users",
        user_id=current_user.id
    )
    await auth_services.UserService.delete(
        current_user_id=current_user.id,
        user_id=user_id,
    )
    return {"message": "User deleted successfully"}


@user_router.delete(
    "/{user_id}/soft/",
)
async def user_soft_delete(
        user_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user),
):
    await auth_services.UserService.check_permission(
        permission_title="delete-users",
        user_id=current_user.id
    )
    await auth_services.UserService.soft_delete(
        current_user_id=current_user.id,
        user_id=user_id,
    )
    return {"message": "User soft deleted successfully"}


@user_router.put(
    "/{user_id}/restore/",
    response_model=auth_schemas.UserResponse
)
async def user_restore(
        user_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user),
):
    await auth_services.UserService.check_permission(
        permission_title="restore-users",
        user_id=current_user.id
    )
    return await auth_services.UserService.restore(
        current_user_id=current_user.id,
        user_id=user_id,
    )


@user_router.get(
    "/{user_id}/role/",
    response_model=list[role_policy_schemas.RoleResponse]
)
async def user_get_all_roles(
        user_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.UserService.check_permission(
        permission_title="update-users",
        user_id=current_user.id,
        request_user_id=user_id
    )
    return await auth_services.UserService.get_all_roles(
        user_id=user_id,
    )


@user_router.post(
    "/{user_id}/role/{role_id}/",
    response_model=list[role_policy_schemas.RoleResponse]
)
async def user_add_role(
        user_id: int,
        role_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.UserService.check_permission(
        permission_title="create-users",
        user_id=current_user.id,
    )
    roles = await auth_services.UserService.add_role(
        current_user_id=current_user.id,
        user_id=user_id,
        role_id=role_id,
    )
    return roles


@user_router.delete(
    "/{user_id}/role/{role_id}/",
    response_model=list[role_policy_schemas.RoleResponse]
)
async def user_delete_role(
        user_id: int,
        role_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.UserService.check_permission(
        permission_title="delete-users",
        user_id=current_user.id
    )
    return await auth_services.UserService.delete_role(
        user_id=user_id,
        role_id=role_id,
    )


@user_router.put("/{user_id}/revert/")
async def user_revert(
        user_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await auth_services.UserService.revert(
        user_id=user_id,
    )
    return {"message": "User revert successfully!"}


@user_router.get(
    "/{user_id}/story",
    response_model=list[log_schemas.Log]
)
async def user_get_all_logs(
        user_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await auth_services.UserService.get_all_logs(
        user_id=user_id
    )
