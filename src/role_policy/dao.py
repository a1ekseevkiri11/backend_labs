from src import dao

from src.role_policy import schemas as role_policy_schemas
from src.role_policy import models as role_policy_models


class RoleDAO(dao.BaseDAO[
                  role_policy_models.Role,
                  role_policy_schemas.RoleCreateDB,
                  role_policy_schemas.RoleUpdateDB,
              ]):
    model = role_policy_models.Role


class PermissionDAO(dao.BaseDAO[
                        role_policy_models.Permission,
                        role_policy_schemas.PermissionCreateDB,
                        role_policy_schemas.PermissionUpdateDB,
                    ]):
    model = role_policy_models.Permission
