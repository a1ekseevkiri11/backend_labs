import asyncio
from turtle import title

from src.role_policy.services import (
    PermissionService,
    RoleService
)
from src.role_policy.schemas import (
    PermissionRequest,
    RoleRequest,
)


from src.auth.models import User
from src.role_policy.models import Role, Permission

SEED_PERMISSION = [
    "get-list-",
    "read-",
    "create-",
    "update-",
    "delete-",
    "restore-",
]


SEED_ROLE = [
    RoleRequest(
        title="Admin",
        description="может все",
    ),
    RoleRequest(
        title="User",
        description="Пользователь может получить список пользователей, читать и обновлять свои данные",
    ),
    RoleRequest(
        title="Guest",
        description="Гость может только получить список пользователей",
    ),
]


async def generation_permission_seed(cls):
    for seed_title in SEED_PERMISSION:
        try:
            title = seed_title+cls.__tablename__
            new_permission = PermissionRequest(
                title=title,
                description=f"user can {title}"
            )
            await PermissionService.add(
                current_user_id=1,
                permission_data=new_permission
            )

        except Exception as ex:
            print(ex)


async def generate_role_seed():
    for role in SEED_ROLE:
        try:
            await RoleService.add(
                current_user_id=1,
                role_data=role
            )
        except Exception as ex:
            print(ex)


async def main():
    await generate_role_seed()
    await generation_permission_seed(User)
    await generation_permission_seed(Permission)
    await generation_permission_seed(Role)


if __name__ == "__main__":
    asyncio.run(main())
