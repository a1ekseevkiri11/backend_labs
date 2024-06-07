import asyncio
from fastapi import (
    HTTPException,
    status,
    Depends,
)
from sqlalchemy import (
    asc,
    desc,
    select,
    delete,
    exists,
    and_,
    MetaData
)
from sqlalchemy.ext.asyncio import AsyncSession

from src.log import schemas as log_schemas
from src.log import models as log_models
from src.log import dao as log_dao
from src.database import async_session_maker
from src.role_policy import models as role_policy_models
from src.models import Base
from src.log.utils import TABLE_MODEL_MAP, convert_dates, convert_isoformat_to_dates


class LogServices:
    @classmethod
    async def add(
            cls,
            session: AsyncSession,
            log_data: log_schemas.LogCreateDB,
    ) -> None:
        log_data_dict = log_data.dict()
        log_data_converted = convert_dates(log_data_dict)
        await log_dao.LogDAO.add(
            session,
            log_data_converted,
        )

    @staticmethod
    async def get_all(
            entity_type: str,
            entity_id: int
    ) -> list[log_schemas.Log]:
        async with async_session_maker() as session:
            db_logs = await log_dao.LogDAO.find_all(
                session,
                and_(
                    log_models.ChangeLog.entity_type == entity_type,
                    log_models.ChangeLog.entity_id == entity_id
                )
            )
        return [log for log in db_logs]

    @staticmethod
    async def revert(
            entity_type: str,
            entity_id: int
    ):
        async with async_session_maker() as session:
            stmt = (
                select(log_models.ChangeLog)
                .filter(log_models.ChangeLog.entity_type == entity_type)
                .filter(log_models.ChangeLog.entity_id == entity_id)
                .order_by(desc(log_models.ChangeLog.id))
                .limit(1)
            )
            result = await session.execute(stmt)
            last_log = result.scalars().first()
            if not last_log:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Log not found"
                )

            if entity_type not in TABLE_MODEL_MAP:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Error logger"
                )

            dao = TABLE_MODEL_MAP[entity_type]

            if not last_log.before_change:
                await dao.delete(
                    session,
                    dao.model.id == entity_id,
                )

            elif not last_log.after_change:
                before_change = convert_isoformat_to_dates(last_log.before_change)
                await dao.add(
                    session,
                    obj_in=before_change,
                )

            else:
                before_change = convert_isoformat_to_dates(last_log.before_change)
                await dao.update(
                    session,
                    dao.model.id == entity_id,
                    obj_in=before_change,
                )

            await log_dao.LogDAO.delete(
                session,
                log_dao.LogDAO.model.id == last_log.id
            )

            await session.commit()


async def main():
    await LogServices.revert(
            entity_type="roles",
            entity_id=4
    )


if __name__ == "__main__":
    asyncio.run(main())
