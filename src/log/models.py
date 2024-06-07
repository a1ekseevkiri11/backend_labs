from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    declared_attr,
    relationship
)
from datetime import datetime
from sqlalchemy import (
    Text,
    DateTime,
    func,
    JSON,
)
from src.models import (
    Base,
)


class ChangeLog(Base):
    __tablename__ = 'change_logs'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(Text,  nullable=False)
    entity_id: Mapped[int] = mapped_column(nullable=False)
    before_change = mapped_column(JSON)
    after_change = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    created_by: Mapped[int]
