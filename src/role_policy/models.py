from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    declared_attr,
    relationship,
    Session
)
import uuid
from datetime import date, datetime
from sqlalchemy import (
    Text,
    ForeignKey,
    func,
    event
)
from src.models import (
    Base,
    BaseServiceFields
)
from src.auth import models


class BaseEntity(BaseServiceFields):
    __abstract__ = True

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cipher: Mapped[str] = mapped_column(Text, nullable=False)


class Role(BaseEntity):
    __tablename__ = 'roles'

    users: Mapped[list["User"]] = relationship(
        "User",
        secondary="users_and_roles",
        back_populates="roles",
        lazy="selectin"
    )

    users_associations: Mapped[list["UsersAndRoles"]] = relationship(
        "UsersAndRoles",
        back_populates="role",
        lazy="selectin"
    )

    permissions: Mapped[list["Permission"]] = relationship(
        back_populates="roles",
        secondary="roles_and_permissions",
        lazy="selectin"
    )

    permissions_associations: Mapped[list["RolesAndPermissions"]] = relationship(
        "RolesAndPermissions",
        back_populates="role",
        lazy="selectin"
    )


class UsersAndRoles(BaseServiceFields):
    __tablename__ = 'users_and_roles'

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)

    user: Mapped["User"] = relationship(
        "User",
        back_populates="roles_associations",
        lazy="selectin"
    )

    role: Mapped["Role"] = relationship(
        "Role",
        back_populates="users_associations",
        lazy="selectin"
    )


class Permission(BaseEntity):
    __tablename__ = 'permissions'

    roles: Mapped[list["Role"]] = relationship(
        "Role",
        back_populates="permissions",
        secondary="roles_and_permissions",
        lazy="selectin"
    )

    roles_associations: Mapped[list["RolesAndPermissions"]] = relationship(
        "RolesAndPermissions",
        back_populates="permission",
        lazy="selectin"
    )


class RolesAndPermissions(BaseServiceFields):
    __tablename__ = 'roles_and_permissions'

    roles_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    permissions_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), primary_key=True)

    role: Mapped[list["Role"]] = relationship(
        "Role",
        back_populates="permissions_associations",
        lazy="selectin"
    )

    permission: Mapped[list["Permission"]] = relationship(
        "Permission",
        back_populates="roles_associations",
        lazy="selectin"
    )
