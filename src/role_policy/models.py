from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    declared_attr,
    relationship
)
import uuid
from datetime import date, datetime
from sqlalchemy import (
    Text,
    Date,
    DateTime,
    ForeignKey,
    func,
)
from src.models import Base
from src.auth import models


class BaseServiceFields(Base):
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[int] = mapped_column(nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[datetime] = mapped_column(nullable=True)


class BaseEntity(BaseServiceFields):
    __abstract__ = True

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cipher: Mapped[str] = mapped_column(Text, nullable=False)


class Role(BaseEntity):
    __tablename__ = 'roles'

    users: Mapped[list["User"]] = relationship(
        back_populates="roles",
        secondary="users_and_roles",
        uselist=True,
        # lazy="selectin"
    )

    permissions: Mapped[list["Permission"]] = relationship(
        back_populates="roles",
        secondary="roles_and_permissions",
        uselist=True,
        # lazy="selectin"
    )


class Permission(BaseEntity):
    __tablename__ = 'permissions'

    roles: Mapped[list["Role"]] = relationship(
        back_populates="permissions",
        secondary="roles_and_permissions",
        uselist=True,
        # lazy="selectin"
    )


class UsersAndRoles(BaseServiceFields):
    __tablename__ = 'users_and_roles'

    users_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    roles_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)


class RolesAndPermissions(BaseServiceFields):
    __tablename__ = 'roles_and_permissions'

    roles_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    permissions_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), primary_key=True)