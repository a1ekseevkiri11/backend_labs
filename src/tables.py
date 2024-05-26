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





class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    birthday: Mapped[date] = mapped_column(Date, nullable=False)


class RevokedToken(Base):
    __tablename__ = 'revoked_tokens'

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
