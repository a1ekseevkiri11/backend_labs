from pydantic import BaseModel, EmailStr
from sqlalchemy import DateTime


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    c_password: str
    birthday: DateTime


class User(BaseModel):
    username: str
    email: EmailStr
    birthday: DateTime


class Token(BaseModel):
    access_token: str
    token_type: str = "Bearer"
