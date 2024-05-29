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


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    birthday: Mapped[date] = mapped_column(Date, nullable=False)

    tokens: Mapped["Token"] = relationship(back_populates="user", uselist=True)


class Token(Base):
    __tablename__ = "tokens"

    hashed_token: Mapped[str] = mapped_column(Text, primary_key=True)
    exp: Mapped[int] = mapped_column(nullable=False)

    user = relationship("User", back_populates="tokens")
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

