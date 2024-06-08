import uuid
from pydantic import (
    BaseModel,
    EmailStr,
    constr,
    Field,
    SecretStr,
    model_validator,
    field_validator,
)
from datetime import date, datetime

from typing import Optional
from typing_extensions import Self

import re


class PermissionRequest(BaseModel):
    title: str
    description: str


class Permission(BaseModel):
    id: int
    title: str
    description: str
    cipher: str
    created_at: datetime
    created_by: int


class PermissionResponse(BaseModel):
    id: int
    title: str
    description: str
    cipher: str
    created_at: datetime
    created_by: int


class PermissionCreateDB(BaseModel):
    title: str
    description: str
    cipher: str
    created_at: Optional[datetime] = None
    created_by: Optional[int] = None
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[int] = None


class PermissionUpdateDB(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None


class RoleRequest(BaseModel):
    title: str
    description: str


class Role(BaseModel):
    id: int
    title: str
    description: str
    cipher: str
    created_at: datetime
    created_by: int


class RoleResponse(BaseModel):
    id: int
    title: str
    description: str
    permissions: list[PermissionResponse]


class RoleCreateDB(BaseModel):
    title: str
    description: str
    cipher: str
    created_at: Optional[datetime] = None
    created_by: Optional[int] = None
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[int] = None


class SoftDeleteDB(BaseModel):
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[int] = None


class RoleUpdateDB(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None

