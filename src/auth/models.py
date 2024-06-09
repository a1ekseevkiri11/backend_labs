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
)
from typing import Optional
from src.models import (
    Base,
    BaseServiceFields,
)
from src.role_policy import models


class User(BaseServiceFields):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    birthday: Mapped[date] = mapped_column(Date, nullable=False)

    tokens: Mapped[list["Token"]] = relationship(back_populates="user")

    roles: Mapped[list["Role"]] = relationship(
        "Role",
        secondary="users_and_roles",
        back_populates="users",
        lazy="selectin"
    )

    roles_associations: Mapped[list["UsersAndRoles"]] = relationship(
        "UsersAndRoles",
        back_populates="user",
        lazy="selectin",
    )

    otp: Mapped["OTP"] = relationship(uselist=False, back_populates="user")


class OTP(Base):
    __tablename__ = "otp"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    code: Mapped[int] = mapped_column()
    exp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count_attempts: Mapped[int] = mapped_column()

    user = relationship("User", back_populates="otp")
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))


class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    exp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user = relationship("User", back_populates="tokens")
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
