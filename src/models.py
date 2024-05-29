from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    declared_attr,
)

from datetime import date, datetime

from sqlalchemy import (
    Text,
    Date,
    DateTime
)


class Base(DeclarativeBase):
    __abstract__ = True
