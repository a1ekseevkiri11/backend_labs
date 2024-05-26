from pydantic import BaseModel, EmailStr
from datetime import date


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    c_password: str
    birthday: date


class User(BaseModel):
    id: int
    username: str


class OutputUser(BaseModel):
    id: int
    username: str
    email: EmailStr
    birthday: date


class Token(BaseModel):
    access_token: str
    token_type: str = "Bearer"
