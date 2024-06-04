from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    declared_attr,
    Query,
)

from datetime import date, datetime
from sqlalchemy import (
    Text,
    Date,
    DateTime,
    func
)
from sqlalchemy_easy_softdelete.mixin import generate_soft_delete_mixin_class


class Base(DeclarativeBase):
    __abstract__ = True


class SoftDeleteMixin(generate_soft_delete_mixin_class()):
    deleted_at: datetime


class BaseServiceFields(Base, SoftDeleteMixin):
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    created_by: Mapped[int] = mapped_column(default=-1)
    deleted_by: Mapped[int] = mapped_column(nullable=True)
