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
            user_id: int,
    ) -> list[dict]:
        async with async_session_maker() as session:
            db_tokens = await auth_dao.TokenDAO.find_all(
                session=session,
                user_id=user_id
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
        user_id,
    ) -> None:
        async with (async_session_maker() as session):
            await auth_dao.TokenDAO.delete(
                session=session,
                user_id=user_id
            )
            await session.commit()

    @classmethod
    async def create(
            cls,
            user_id: int,
            expire_timedelta: timedelta | None = None,
            access_expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    ) -> auth_schemas.Token:

        now = datetime.now(timezone.utc)

        if expire_timedelta:
            exp = now + expire_timedelta
        else:
            exp = now + timedelta(minutes=access_expire_minutes)

        async with (async_session_maker() as session):
            count_tokens = await auth_dao.TokenDAO.count(
                session,
                user_id=user_id
            )
            if count_tokens >= settings.auth_jwt.count_tokens:
                stmt = (
                    select(auth_models.Token)
                    .filter(auth_models.Token.user_id == user_id)
                    .order_by(asc(auth_models.Token.exp))
                    .limit(1)
                )
                result = await session.execute(stmt)
                oldest_token = result.scalars().first()
                if oldest_token:
                    await auth_dao.TokenDAO.delete(
                        session=session,
                        id=oldest_token.id
                    )

            db_token = await auth_dao.TokenDAO.add(
                session,
                auth_schemas.TokenCreateDB(
                    user_id=user_id,
                    exp=exp
                )
            )
            await session.commit()

        payload = {
            "id": db_token.id,
            "sub": str(user_id),
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
    @classmethod
    async def add(
            cls,
            user_data: auth_schemas.RegisterRequest,
    ) -> auth_schemas.User:
        async with async_session_maker() as session:
            user_exist = await auth_dao.UserDao.find_one_or_none(session, username=user_data.username)
            if user_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this username already exists"
                )

            user_exist = await auth_dao.UserDao.find_one_or_none(session, email=user_data.email)

            if user_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this email already exists"
                )

            db_user = await auth_dao.UserDao.add(
                session,
                auth_schemas.UserCreateDB(
                    **user_data.model_dump(),
                    hashed_password=get_hash(user_data.password)
                )
            )
            await session.commit()

        return db_user

    @classmethod
    async def get_user(
            cls,
            user_id: int
    ) -> auth_schemas.User:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDao.find_one_or_none(
                session,
                id=user_id
            )
        if db_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        return db_user


class AuthService:
    @classmethod
    async def login(
            cls,
            user_data: auth_schemas.LoginRequest,
    ) -> Optional[auth_schemas.User]:
        async with async_session_maker() as session:
            db_user = await auth_dao.UserDao.find_one_or_none(
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

        except Exception as ex:
            raise exceptions.InvalidTokenException

        user = await UserService.get_user(user_id)
        user.token = token
        return user
