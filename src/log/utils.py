from src.role_policy import models as role_policy_models
from src.auth import models as auth_models
from datetime import date, datetime
from typing import Any

from src.role_policy import dao as role_policy_dao
from src.log import dao as log_dao
from src.auth import dao as auth_dao


TABLE_MODEL_MAP = {
    auth_models.User.__tablename__: auth_dao.UserDAO,
    role_policy_models.Role.__tablename__: role_policy_dao.RoleDAO,
    role_policy_models.Permission.__tablename__: role_policy_dao.PermissionDAO,
}


def convert_dates(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: convert_dates(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_dates(item) for item in obj]
    elif isinstance(obj, (date, datetime)):
        return obj.isoformat()
    return obj


def convert_isoformat_to_dates(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: convert_isoformat_to_dates(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_isoformat_to_dates(item) for item in obj]
    elif isinstance(obj, str):
        try:
            return datetime.fromisoformat(obj).date()
        except ValueError:
            return obj
    return obj
