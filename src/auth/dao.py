from src.auth import models
from src.auth import schemas
from src import dao


class UserDAO(dao.BaseDAO[models.User, schemas.UserCreateDB, schemas.UserUpdateDB]):
    model = models.User


class TokenDAO(dao.BaseDAO[models.Token, schemas.TokenCreateDB, schemas.TokenUpdateDB]):
    model = models.Token


class OTPDAO(dao.BaseDAO[models.OTP, schemas.OTPCreateDB, schemas.OTPUpdateDB]):
    model = models.OTP