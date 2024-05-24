from fastapi import FastAPI, APIRouter
from src.settings import settings

app = FastAPI(
    title="backend_lab",
    description="API Backend Lab",
    debug=settings.debug,
)


@app.get("/")
def hello_index():
    return {
        "message": "Hello index!",
    }