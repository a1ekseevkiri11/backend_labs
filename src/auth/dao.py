from src.auth import models
from src.auth import schemas
from src import dao


class UserDao(dao.BaseDAO[models.User, schemas.UserCreateDB, schemas.UserUpdateDB]):
    model = models.User


class TokenDAO(dao.BaseDAO[models.Token, schemas.TokenCreateDB, schemas.TokenUpdateDB]):
    model = models.Token
