from fastapi import (
    APIRouter,
    Depends,
    Response,
    Request,
    status,
    HTTPException,
)

from src.auth import schemas as auth_schemas
from src.auth import services as auth_services
from src.role_policy import schemas as role_policy_schemas
from src.role_policy import services as role_policy_services
from src import exceptions
from src.settings import settings


permission_router = APIRouter(tags=["Permission"], prefix="/ref/policy/permission")


@permission_router.get(
    "/{permission_id}/",
    response_model=role_policy_schemas.PermissionResponse,
)
async def permission_get(
        permission_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.PermissionService.get(
        permission_id=permission_id,
    )


@permission_router.get(
    "/",
    response_model=list[role_policy_schemas.PermissionResponse],
)
async def permission_get_all(
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.PermissionService.get_all()


@permission_router.post(
    "/",
    response_model=role_policy_schemas.PermissionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def permission_add(
        permission_data: role_policy_schemas.PermissionRequest,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.PermissionService.add(
        current_user_id=current_user.id,
        permission_data=permission_data
    )


@permission_router.put("/{permission_id}/")
async def permission_update(
        permission_id: int,
        permission_data: role_policy_schemas.PermissionRequest,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.PermissionService.update(
        permission_id=permission_id,
        permission_data=permission_data
    )


@permission_router.delete("/{permission_id}/")
async def permission_delete(
        permission_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await role_policy_services.PermissionService.delete(
        permission_id=permission_id,
    )
    return {"message": "Permission deleted successfully"}


role_router = APIRouter(tags=["Role"], prefix="/ref/policy/role")


@role_router.get("/{role_id}/", response_model=role_policy_schemas.RoleResponse)
async def role_get(
        role_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.get(
        role_id=role_id,
    )


@role_router.get(
    "/",
    response_model=list[role_policy_schemas.RoleResponse],
)
async def role_get_all(
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.get_all()


@role_router.post(
    "/",
    response_model=role_policy_schemas.RoleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def role_add(
        role_data: role_policy_schemas.RoleRequest,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.add(
        role_data=role_data,
        current_user_id=current_user.id,
    )


@role_router.put(
    "/{role_id}/",
    response_model=role_policy_schemas.RoleResponse,
)
async def role_update(
        role_id: int,
        role_data: role_policy_schemas.RoleRequest,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.update(
        role_id=role_id,
        role_data=role_data,
    )


@role_router.delete("/{role_id}/")
async def role_delete(
        role_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await role_policy_services.RoleService.delete(
        role_id=role_id,
    )
    return {"message": "Role deleted successfully"}


@role_router.delete("/{role_id}/soft")
async def role_soft_delete(
        role_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    await role_policy_services.RoleService.soft_delete(
        current_user_id=current_user.id,
        role_id=role_id,
    )
    return {"message": "Role soft_deleted successfully"}


@role_router.delete(
    "/{role_id}/refresh",
    response_model=role_policy_schemas.RoleResponse,
)
async def role_refresh(
        role_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.refresh(
        role_id=role_id,
    )


@role_router.get(
    "/{role_id}/permission/",
    response_model=list[role_policy_schemas.PermissionResponse]
)
async def role_get_all_permission(
        role_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.get_all_permission(
        role_id=role_id,
    )


@role_router.post(
    "/{role_id}/permission/{permission_id}/",
    response_model=list[role_policy_schemas.PermissionResponse]
)
async def role_add_permission(
        role_id: int,
        permission_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.add_permission(
        role_id=role_id,
        permission_id=permission_id,
        current_user_id=current_user.id
    )


@role_router.delete(
    "/{role_id}/permission/{permission_id}/",
    response_model=list[role_policy_schemas.PermissionResponse]
)
async def role_delete_permission(
        role_id: int,
        permission_id: int,
        current_user: auth_schemas.User = Depends(auth_services.AuthService.get_current_user)
):
    return await role_policy_services.RoleService.delete_permission(
        role_id=role_id,
        permission_id=permission_id,
    )
