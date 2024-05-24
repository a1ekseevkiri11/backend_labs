from fastapi import APIRouter, Depends, Response

router = APIRouter(tags=["Auth"], prefix="api/auth")



@router.post("/login/")
async def login(
):
    pass


@router.post("/register/")
async def register(
):
    pass

@router.get("/me/",)
async def user(
):
    pass


@router.post("/out/")
async def register(
):
    pass

@router.get("/tokens/")
async def user(
):
    pass


@router.post("/out_all/")
async def register(
):
    pass

