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
    ForeignKey
)
from src.models import Base
from src.role_policy import models


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    birthday: Mapped[date] = mapped_column(Date, nullable=False)

    tokens: Mapped["Token"] = relationship(back_populates="user", uselist=True)

    roles: Mapped[list["Role"]] = relationship(
        back_populates="users",
        secondary="users_and_roles",
        uselist=True,
        lazy="selectin"
    )


class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    exp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user = relationship("User", back_populates="tokens")
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
