from datetime import timedelta, datetime, timezone
import jwt
from fastapi import (
    HTTPException,
    status,
    Depends,
)
from sqlalchemy import (
    asc,
    select,
    delete
)
from typing import Optional
from datetime import datetime


from src.role_policy import schemas as role_policy_schemas
from src.database import async_session_maker
from src.role_policy import dao as role_policy_dao
from src.role_policy import models as role_policy_models


class RoleService:
    @staticmethod
    async def add(
            current_user_id: int,
            role_data: role_policy_schemas.RoleRequest
    ) -> role_policy_schemas.Role:
        async with async_session_maker() as session:
            role_exist = await role_policy_dao.RoleDAO.find_one_or_none(
                session,
                role_policy_models.Role.title == role_data.title
            )
            if role_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Role with this title already exist"
                )

            cipher = "cipher"

            create_db_role = role_policy_schemas.RoleCreateDB(
                **role_data.model_dump(),
                created_by=current_user_id,
                cipher=cipher
            )

            db_role = await role_policy_dao.RoleDAO.add(
                session,
                create_db_role
            )
            await session.commit()

        return db_role

    @staticmethod
    async def get(
            role_id
    ) -> role_policy_schemas.Role:
        async with async_session_maker() as session:
            db_role = await role_policy_dao.RoleDAO.find_one_or_none(
                session=session,
                id=role_id
            )

        if db_role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
            )

        return db_role

    @staticmethod
    async def get_all() -> list[role_policy_schemas.Role]:
        async with async_session_maker() as session:
            db_role = await role_policy_dao.RoleDAO.find_all(
                session=session,
            )

        return [role for role in db_role]

    @classmethod
    async def update(
            cls,
            role_id: int,
            role_data: role_policy_schemas.RoleRequest,
    ) -> role_policy_schemas.Role:
        await cls.get(role_id=role_id)
        async with async_session_maker() as session:
            role_exist = await role_policy_dao.RoleDAO.find_one_or_none(
                session,
                role_policy_models.Role.title == role_data.title,
            )
            if role_exist and role_exist.id != role_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Role with this title already exist"
                )

            update_db_role = role_policy_schemas.RoleUpdateDB(
                **role_data.model_dump(),
            )

            db_role = await role_policy_dao.RoleDAO.update(
                session,
                role_policy_models.Role.id == role_id,
                obj_in=update_db_role,
            )
            await session.commit()

        return db_role

    @classmethod
    async def delete(
            cls,
            role_id: int,
    ) -> None:
        await cls.get(role_id=role_id)
        async with async_session_maker() as session:
            await role_policy_dao.RoleDAO.delete(
                session=session,
                id=role_id,
            )
            await session.commit()

    @staticmethod
    async def get_all_permission(
            role_id: int
    ) -> list[role_policy_schemas.Permission]:
        async with async_session_maker() as session:
            db_role = await role_policy_dao.RoleDAO.find_one_or_none(
                session,
                role_policy_models.Role.id == role_id
            )
            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
                )
            return db_role.permissions

    @classmethod
    async def add_permission(
            cls,
            current_user_id: int,
            role_id: int,
            permission_id: int,
    ) -> list[role_policy_schemas.Permission]:
        async with async_session_maker() as session:
            db_role = await role_policy_dao.RoleDAO.find_one_or_none(
                session,
                role_policy_models.Role.id == role_id
            )

            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
                )

            db_permission = await role_policy_dao.PermissionDAO.find_one_or_none(
                session,
                role_policy_models.Permission.id == permission_id
            )

            if db_permission is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
                )

            for permission in db_role.permissions:
                if permission.id == permission_id:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT, detail="Role with this permission already exist",
                    )

            db_role.permissions_associations.append(
                role_policy_models.RolesAndPermissions(
                    permission=db_permission,
                    created_by=current_user_id
                )
            )

            await session.commit()
            return await cls.get_all_permission(role_id=role_id)

    @classmethod
    async def delete_permission(
            cls,
            role_id: int,
            permission_id: int,
    ) -> list[role_policy_schemas.Permission]:
        async with async_session_maker() as session:
            db_role = await role_policy_dao.RoleDAO.find_one_or_none(
                session,
                role_policy_models.Role.id == role_id
            )

            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
                )

            db_permission = await role_policy_dao.PermissionDAO.find_one_or_none(
                session,
                role_policy_models.Permission.id == permission_id
            )

            if db_permission is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
                )

            for permission in db_role.permissions:
                if permission.id == permission_id:
                    db_role.permissions.remove(db_permission)
                    await session.commit()
                    return await cls.get_all_permission(role_id=role_id)

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Role with this permission already exist",
            )

    @classmethod
    async def soft_delete(
            cls,
            current_user_id: int,
            role_id: int,
    ) -> None:
        async with async_session_maker() as session:
            db_role = await role_policy_dao.RoleDAO.find_one_or_none(
                session,
                role_policy_models.Role.id == role_id
            )

            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
                )
            now = datetime.now(timezone.utc)
            db_role.deleted_at = now
            db_role.deleted_by = current_user_id
            await session.commit()

    @classmethod
    async def refresh(
            cls,
            role_id: int,
    ) -> role_policy_schemas.Role:
        async with async_session_maker() as session:
            db_role = await role_policy_dao.RoleDAO.find_one_or_none_with_deleted(
                session,
                role_policy_models.Role.id == role_id
            )

            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
                )

            db_role.deleted_at = None
            db_role.deleted_by = None
            await session.commit()
            return await cls.get(role_id=role_id)


class PermissionService:
    @staticmethod
    async def add(
            current_user_id: int,
            permission_data: role_policy_schemas.PermissionRequest
    ) -> role_policy_schemas.Permission:
        async with async_session_maker() as session:
            permission_exist = await role_policy_dao.PermissionDAO.find_one_or_none(
                session,
                role_policy_models.Permission.title == permission_data.title
            )
            if permission_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Permission with this title already exist"
                )

            cipher = "cipher"

            create_db_permission = role_policy_schemas.PermissionCreateDB(
                **permission_data.model_dump(),
                created_by=current_user_id,
                cipher=cipher
            )

            db_permission = await role_policy_dao.PermissionDAO.add(
                session,
                create_db_permission
            )
            await session.commit()

        return db_permission

    @staticmethod
    async def get(
            permission_id
    ) -> role_policy_schemas.Permission:
        async with async_session_maker() as session:
            db_permission = await role_policy_dao.PermissionDAO.find_one_or_none(
                session=session,
                id=permission_id
            )

        if db_permission is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
            )

        return db_permission

    @staticmethod
    async def get_all() -> list[role_policy_schemas.Permission]:
        async with async_session_maker() as session:
            db_permission = await role_policy_dao.PermissionDAO.find_all(
                session=session,
            )

        return [permission for permission in db_permission]

    @classmethod
    async def update(
            cls,
            permission_id: int,
            permission_data: role_policy_schemas.PermissionRequest,
    ) -> role_policy_schemas.Permission:
        await cls.get(permission_id=permission_id)
        async with async_session_maker() as session:
            permission_exist = await role_policy_dao.PermissionDAO.find_one_or_none(
                session,
                role_policy_models.Permission.title == permission_data.title,
            )
            if permission_exist and permission_exist.id != permission_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Permission with this title already exist"
                )

            update_db_permission = role_policy_schemas.PermissionUpdateDB(
                **permission_data.model_dump(),
            )

            db_permission = await role_policy_dao.PermissionDAO.update(
                session,
                role_policy_models.Permission.id == permission_id,
                obj_in=update_db_permission,
            )
            await session.commit()

        return db_permission

    @classmethod
    async def delete(
            cls,
            permission_id: int,
    ) -> None:
        await cls.get(permission_id=permission_id)
        async with async_session_maker() as session:
            await role_policy_dao.PermissionDAO.delete(
                session=session,
                id=permission_id,
            )
            await session.commit()

    # TODO: дописать мягкое удаление и востановление
