from src.log import models
from src.log import schemas
from src import dao


class LogDAO(dao.BaseDAO[models.ChangeLog, schemas.LogCreateDB, schemas.LogUpdateDB]):
    model = models.ChangeLog
