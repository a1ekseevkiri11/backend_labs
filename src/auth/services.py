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
    delete,
    exists,
    and_
)
from typing import Optional
from datetime import datetime


from src.auth import schemas as auth_schemas
from src.auth import dao as auth_dao
from src.auth import models as auth_models
from src.database import async_session_maker
from src.settings import settings
from src.auth.utils import (
    get_hash,
    is_matched_hash,
    OAuth2PasswordBearerWithCookie
)
from src import exceptions
from src.role_policy import dao as role_policy_dao
from src.role_policy import models as role_policy_models
from src.role_policy import schemas as role_policy_schemas


oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="/api/auth/login/")


class JWTServices:
    @classmethod
    def encode(
            cls,
            payload: dict,
            private_key: str = settings.auth_jwt.private_key_path.read_text(),
            algorithm: str = settings.auth_jwt.algorithm,
    ) -> str:
        return jwt.encode(payload, key=private_key, algorithm=algorithm)

    @classmethod
    def decode(
            cls,
            token: str,
            public_key: str = settings.auth_jwt.public_key_path.read_text(),
            algorithms: str = settings.auth_jwt.algorithm
    ) -> auth_schemas.Token:
        try:
            return jwt.decode(token, key=public_key, algorithms=[algorithms])
        except ValueError as ex:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Could not validate credentials: {ex}")

    @classmethod
    async def get_all(
            cls,
            current_user_id: int,
    ) -> list[dict]:
        async with async_session_maker() as session:
            db_tokens = await auth_dao.TokenDAO.find_all(
                session=session,
                user_id=current_user_id
            )
            return [{"id": token.id, "exp": token.exp} for token in db_tokens]

    @classmethod
    async def delete(
            cls,
            token: str,
    ) -> None:
        async with async_session_maker() as session:
            token_id = JWTServices.decode(token=token).get("id")
            token = await auth_dao.TokenDAO.find_one_or_none(
                session=session,
                id=token_id
            )
            if token:
                await auth_dao.TokenDAO.delete(
                    session=session,
                    id=token_id
                )
            await session.commit()

    @classmethod
    async def delete_all(
        cls,
        current_user_id,
    ) -> None:
        async with (async_session_maker() as session):
            await auth_dao.TokenDAO.delete(
                session=session,
                user_id=current_user_id
            )
            await session.commit()

    @classmethod
    async def create(
            cls,
            current_user_id: int,
            expire_timedelta: timedelta | None = None,
            access_expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    ) -> auth_schemas.Token:
        if settings.auth_jwt.count_tokens < 0:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="the number of tokens must be greater than 0")

        now = datetime.now(timezone.utc)

        if expire_timedelta:
            exp = now + expire_timedelta
        else:
            exp = now + timedelta(minutes=access_expire_minutes)

        async with (async_session_maker() as session):
            db_token = await auth_dao.TokenDAO.add(
                session,
                auth_schemas.TokenCreateDB(
                    user_id=current_user_id,
                    exp=exp
                )
            )
            count_tokens = await auth_dao.TokenDAO.count(
                session,
                user_id=current_user_id
            )

            if count_tokens >= settings.auth_jwt.count_tokens:
                stmt = (
                    select(auth_models.Token)
                    .filter(auth_models.Token.user_id == current_user_id)
                    .order_by(asc(auth_models.Token.exp))
                    .limit(count_tokens - settings.auth_jwt.count_tokens)
                )
                result = await session.execute(stmt)
                oldest_tokens = result.scalars().all()
                for oldest_token in oldest_tokens:
                    await auth_dao.TokenDAO.delete(
                        session=session,
                        id=oldest_token.id
                    )

            await session.commit()

            payload = {
                "id": db_token.id,
                "sub": str(current_user_id),
                "exp": exp,
                "iat": now,
            }

            token = auth_schemas.Token(
                access_token=cls.encode(payload=payload)
            )

            return token

    @classmethod
    async def is_valid(
            cls,
            token: str,
    ) -> bool:
        async with async_session_maker() as session:
            token_id = JWTServices.decode(token=token).get("id")

            db_token = await auth_dao.TokenDAO.find_one_or_none(
                session=session,
                id=token_id
            )
            if db_token is None:
                return False
            if db_token.exp > datetime.now():
                await cls.delete(token)
                return False
            return True


class UserService:
    @staticmethod
    async def add(
            user_data: auth_schemas.RegisterRequest,
            current_user_id: Optional[int] = None,
    ) -> auth_schemas.User:
        async with async_session_maker() as session:
            user_exist = await auth_dao.UserDAO.find_one_or_none(session, username=user_data.username)
            if user_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this username already exists"
                )

            user_exist = await auth_dao.UserDAO.find_one_or_none(session, email=user_data.email)

            if user_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this email already exists"
                )
            if current_user_id:
                db_user = await auth_dao.UserDAO.add(
                    session,
                    auth_schemas.UserCreateDB(
                        **user_data.model_dump(),
                        hashed_password=get_hash(user_data.password),
                        created_by=current_user_id
                    )
                )
            else:
                db_user = await auth_dao.UserDAO.add(
                    session,
                    auth_schemas.UserCreateDB(
                        **user_data.model_dump(),
                        hashed_password=get_hash(user_data.password),
                    )
                )
                db_user.created_by = db_user.id
            await session.commit()

        return db_user

    @staticmethod
    async def get(
            user_id: int
    ) -> auth_schemas.User:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDAO.find_one_or_none(
                session,
                id=user_id
            )
        if db_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        return db_user

    @staticmethod
    async def get_all(
    ) -> list[auth_schemas.User]:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDAO.find_all(
                session=session,
            )

        return [user for user in db_user]

    @classmethod
    async def update(
            cls,
            user_id: int,
            user_data: auth_schemas.UserRequest,
    ) -> auth_schemas.User:
        await cls.get(user_id=user_id)
        async with async_session_maker() as session:
            user_exist = await auth_dao.UserDAO.find_one_or_none(
                session,
                auth_models.User.username == user_data.username,
            )
            if user_exist and user_exist.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this username already exist"
                )

            user_exist = await auth_dao.UserDAO.find_one_or_none(
                session,
                auth_models.User.email == user_data.email,
            )
            if user_exist and user_exist.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this email already exist"
                )

            update_db_user = auth_schemas.UserUpdateDB(
                **user_data.model_dump(),
            )

            db_permission = await auth_dao.UserDAO.update(
                session,
                auth_models.User.id == user_id,
                obj_in=update_db_user,
            )
            await session.commit()

        return db_permission

    @classmethod
    async def delete(
            cls,
            user_id: int
    ) -> None:
        await cls.get(user_id=user_id)
        async with async_session_maker() as session:
            await auth_dao.UserDAO.delete(
                session=session,
                id=user_id,
            )
            await session.commit()

    @classmethod
    async def soft_delete(
            cls,
            current_user_id: int,
            user_id: int,
    ) -> None:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDAO.find_one_or_none(
                session,
                auth_schemas.User.id == user_id
            )

            if db_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )
            now = datetime.now(timezone.utc)
            db_user.deleted_at = now
            db_user.deleted_by = current_user_id
            await session.commit()

    @classmethod
    async def restore(
            cls,
            user_id: int,
    ) -> auth_schemas.User:
        async with async_session_maker() as session:
            db_role = await auth_dao.UserDAO.find_one_or_none_with_deleted(
                session,
                auth_schemas.User.id == role_id
            )

            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
                )

            db_role.deleted_at = None
            db_role.deleted_by = None
            await session.commit()
            return await cls.get(user_id=user_id)

    @staticmethod
    async def get_all_roles(
            user_id: int,
    ) -> list[role_policy_schemas.Role]:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDAO.find_one_or_none(
                session=session,
                id=user_id,
            )
            if db_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )
            return db_user.roles

    @staticmethod
    async def check_role(
            user_id: int,
            role_title: str
    ) -> bool:
        async with async_session_maker() as session:
            stm = (
                select(exists().where(
                    and_(
                        auth_models.User.id == user_id,
                        role_policy_models.UsersAndRoles.user_id == auth_models.User.id,
                        role_policy_models.UsersAndRoles.role_id == role_policy_models.Role.id,
                        role_policy_models.Role.title == role_title
                    )
                ))
            )
            role_exists = await session.execute(stm)
            return role_exists.scalar()

    @classmethod
    async def check_permission(
            cls,
            user_id: int,
            permission_title: str,
            request_user_id: Optional[int] = None
    ):
        if await cls.check_role(
            user_id=user_id,
            role_title="Admin"
        ):
            return

        if request_user_id and request_user_id != user_id and await cls.check_role(
            role_title="User",
            user_id=user_id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="user with the “User” role cannot work with data other than his own"
            )

        async with async_session_maker() as session:
            stm = (
                select(exists().where(
                    and_(
                        user_id == auth_models.User.id,
                        auth_models.User.id == role_policy_models.UsersAndRoles.user_id,
                        role_policy_models.UsersAndRoles.role_id == role_policy_models.RolesAndPermissions.roles_id,
                        role_policy_models.RolesAndPermissions.permissions_id == role_policy_models.Permission.id,
                        role_policy_models.Permission.title == permission_title
                    )
                ))
            )
            permission_exists = await session.execute(stm)
            if not permission_exists.scalar():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User haven't permission {permission_title}",
                )

    @classmethod
    async def add_role(
            cls,
            current_user_id: int,
            user_id: int,
            role_id: int,
    ) -> list[role_policy_schemas.Role]:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDAO.find_one_or_none(
                session=session,
                id=user_id,
            )
            if db_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )
            db_role = await role_policy_dao.RoleDAO.find_one_or_none(
                session=session,
                id=role_id
            )
            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
                )
            for role in db_user.roles:
                if role.id == role_id:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT, detail="User with this role already exist",
                    )
            db_user.roles_associations.append(
                role_policy_models.UsersAndRoles(
                    role=db_role,
                    created_by=current_user_id
                )
            )
            await session.commit()
            return await cls.get_all_roles(user_id=user_id)

    @classmethod
    async def delete_role(
            cls,
            user_id: int,
            role_id: int,
    ) -> list[role_policy_schemas.Role]:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDAO.find_one_or_none(
                session=session,
                id=user_id,
            )
            if db_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found",
                )
            db_role = await role_policy_dao.RoleDAO.find_one_or_none(
                session=session,
                id=role_id
            )
            if db_role is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Role not found",
                )
            for role in db_user.roles:
                if role.id == role_id:
                    db_user.roles.remove(db_role)
                    await session.commit()
                    return await cls.get_all_roles(user_id=user_id)

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User does not have this role",
            )


class AuthService:
    @staticmethod
    async def login(
            user_data: auth_schemas.LoginRequest,
    ) -> Optional[auth_schemas.User]:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDAO.find_one_or_none(
                session,
                username=user_data.username
            )

        if db_user and is_matched_hash(
            word=user_data.password,
            hashed=db_user.hashed_password
        ):
            return db_user

        return None

    @classmethod
    async def get_current_user(
            cls,
            token: str = Depends(oauth2_scheme),
    ) -> Optional[auth_schemas.User]:
        try:
            payload = JWTServices.decode(token=token)
            if not await JWTServices.is_valid(token=token):
                raise exceptions.InvalidTokenException

            user_id = payload.get("sub")

            if user_id is None:
                raise exceptions.InvalidTokenException

        except Exception:
            raise exceptions.InvalidTokenException

        current_user = await UserService.get(user_id)

        current_user.token = token
        return current_user
