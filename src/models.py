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
    DateTime,
    func,
)


class Base(DeclarativeBase):
    __abstract__ = True


class BaseServiceFields(Base):
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    created_by: Mapped[int] = mapped_column(default=-1)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[int] = mapped_column(nullable=True)
