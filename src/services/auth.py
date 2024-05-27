from datetime import timedelta, datetime, timezone
from typing import Annotated
import bcrypt
import jwt

from fastapi import Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src import tables
from src.models import auth as auth_model
from src.settings import settings


oauth_schema = OAuth2PasswordBearer(tokenUrl="/api/auth/login/")


class JWTServices:
    @staticmethod
    def encode_jwt(
            payload: dict,
            private_key: str = settings.auth_jwt.private_key_path.read_text(),
            algorithm: str = settings.auth_jwt.algorithm,
            expire_timedelta: timedelta | None = None,
            expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    ):

        to_encode = payload.copy()
        now = datetime.now(timezone.utc)

        if expire_timedelta:
            expire = now + expire_timedelta
        else:
            expire = now + timedelta(minutes=expire_minutes)

        to_encode.update(
            exp=expire,
            iat=now,
        )

        return jwt.encode(to_encode, key=private_key, algorithm=algorithm)

    @staticmethod
    def decode_jwt(
            token: str | bytes,
            public_key: str = settings.auth_jwt.public_key_path.read_text(),
            algorithms: str = settings.auth_jwt.algorithm) -> dict:
        try:
            return jwt.decode(token, key=public_key, algorithms=[algorithms])
        except ValueError as ex:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Could not validate credentials: {ex}")


class AuthServices:

    def hash_password(self, password: str) -> bytes:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def validate_password(self, password: str, hash_password: bytes) -> bool:
        return bcrypt.checkpw(password.encode(), hash_password)


    def create_token(self, user: tables.User) -> auth_model.Token:
        user_data = auth_model.User(
            id=user.id,
            username=user.username,
        )

        payload = {
            "sub": str(user_data.id),
            "user": user_data.dict()
        }

        return auth_model.Token(access_token=JWTServices.encode_jwt(payload))

    async def validate_token(
            self,
            session: AsyncSession,
            token: str,
    ):
        stmt = select(tables.RevokedToken).where(tables.RevokedToken.token == token)
        db_response = await session.execute(stmt)
        db_token = db_response.scalar()

        if db_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED
            )

        try:
            info_token = JWTServices.decode_jwt(token)
        except ValueError as ex:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        return token

    async def current_user(
            self,
            session: AsyncSession,
            token: str,
    ) -> auth_model.OutputUser:

        try:
            confirm_user = JWTServices.decode_jwt(token).get("user")
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        user_id = confirm_user.get("id")
        stmt = select(tables.User).where(tables.User.id == user_id)
        db_response = await session.execute(stmt)
        user = db_response.scalar()

        if user:
            return auth_model.OutputUser(
                id=user.id,
                username=user.username,
                email=user.email,
                birthday=user.birthday
            )

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


    async def login(
            self,
            user_data: auth_model.LoginRequest,
            session: AsyncSession
    ) -> auth_model.Token:

        stmt = select(tables.User).where(tables.User.username == user_data.username)
        db_response = await session.execute(stmt)
        user = db_response.scalar()

        if user:
            if self.validate_password(user_data.password, str.encode(user.password, encoding="utf-8")):
                return self.create_token(user=user)

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Incorrect login or password")

    async def register(
            self,
            user_data: auth_model.RegisterRequest,
            session: AsyncSession
    ) -> auth_model.OutputUser:

        stmt = select(tables.User).where(tables.User.username == user_data.username)
        db_response = await session.execute(stmt)
        db_user = db_response.scalar()

        if db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User with this username already exists",
                headers={
                    "WWW-Authenticate": 'Bearer'
                }
            )

        stmt = select(tables.User).where(tables.User.email == user_data.email)
        db_response = await session.execute(stmt)
        db_user = db_response.scalar()

        if db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User with this email already exists",
                headers={
                    "WWW-Authenticate": 'Bearer'
                }
            )

        user = tables.User(
            username=user_data.username,
            password=str(self.hash_password(user_data.password)).replace("b'", "").replace("'", ""),
            email=user_data.email,
            birthday=user_data.birthday,
        )
        session.add(user)
        await session.commit()

        return auth_model.OutputUser(
            id=user.id,
            username=user.username,
            email=user.email,
            birthday=user.birthday
        )

    async def logout(
            self,
            token: str,
            session: AsyncSession,
    ):
        revoked_at = JWTServices.decode_jwt(token).get("exp")
        revoked_at = datetime.fromtimestamp(revoked_at, tz=timezone.utc)

        db_token = tables.RevokedToken(
            token=token,
            revoked_at=revoked_at
        )
        session.add(db_token)
        await session.commit()

        return Response(content='Success!', status_code=200)


services = AuthServices()
