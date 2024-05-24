from datetime import timedelta, datetime

import bcrypt
import jwt

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPBasic
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src import tables
from src.models import auth
from src import settings


oauth_schema = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class AuthServices:
    @classmethod
    def hash_password(cls, password: str):
        return bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        )

    @classmethod
    def validate_password(cls, password: str, hash_password: bytes) -> bool:
        return bcrypt.checkpw(
            password.encode(),
            hash_password
        )

    @classmethod
    def encode_jwt(
            cls,
            payload: dict,
            private_key: str = settings.auth_jwt.private_key_path.read_text(),
            algorithm: str = settings.auth_jwt.algorithm,
            expire_timedelta: timedelta | None = None,
            expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    ):

        to_encode = payload.copy()
        now = datetime.utcnow()

        if expire_timedelta:
            expire = now + expire_timedelta
        else:
            expire = now + timedelta(minutes=expire_minutes)

        to_encode.update(
            exp=expire,  # Время, когда токен закончит свою работу
            iat=now,  # Время, когда выпущен токен
        )

        return jwt.encode(to_encode, key=private_key, algorithm=algorithm)

    @classmethod
    def decode_jwt(
            cls,
            token: str | bytes,
            public_key: str = settings.auth_jwt.public_key_path.read_text(),
            algorithm: str = settings.auth_jwt.algorithm,
    ) -> dict:

        return jwt.decode(token, key=public_key, algorithms=[algorithm])

    async def validate_token(
            self,
            token,
    ) -> auth.User:

        confirm_user = self.decode_jwt(token).get("user")

        try:
            user = auth.User.parse_obj(confirm_user)
        except ValidationError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not validate credentials") from None

        return user

    async def get_current_user(self, token: str = Depends(oauth_schema)) -> auth.User:
        return await self.validate_token(token)

    def create_token(self, user: tables.User, roles) -> auth.Token:
        userdata = auth.User(
            id=user.id,
            username=user.username,
            roles=roles
        )

        payload = {
            "sub": str(userdata.id),
            "user": userdata.dict()
        }

        return auth.Token(access_token=self.encode_jwt(payload))


services = AuthServices()
