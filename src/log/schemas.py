import uuid
from pydantic import (
    BaseModel,
    EmailStr,
    Json
)
from datetime import date, datetime

from typing import Any, Optional


class LogResponse(BaseModel):
    id: int
    entity_type: str
    entity_id: int
    before_change: Json[Any]
    after_change: Json[Any]
    created_at: datetime
    created_by: int


class Log(BaseModel):
    id: int
    entity_type: str
    entity_id: int
    before_change: Any
    after_change: Any


class LogCreateDB(BaseModel):
    entity_type: str
    entity_id: int
    before_change: Optional[Any] = None
    after_change:  Optional[Any] = None
    created_by: int


class LogUpdateDB(BaseModel):
    before_change: Json[Any]
    after_change: Json[Any]


