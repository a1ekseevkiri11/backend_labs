from fastapi import APIRouter, Depends, Response
from src.models import auth


router = APIRouter(tags=["Auth"], prefix="/auth")


@router.post("/login/", response_model=auth.LoginRequest)
async def login(
):
    pass


@router.post("/register/", response_model=auth.RegisterRequest)
async def register(
):
    pass


@router.get("/me/")
async def user(
):
    return {"data": "Я"}


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

