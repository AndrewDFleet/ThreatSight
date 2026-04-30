import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import config
from db.database import init_db
from core.engine_runner import create_runner
from api.routes import router
from api.websocket import ws_endpoint

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    runner = create_runner()
    await runner.start()
    yield
    runner.stop()


app = FastAPI(
    title="ThreatSight",
    description="Real-time network intrusion detection with AI-powered threat analysis",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)
app.add_api_websocket_route("/ws", ws_endpoint)
app.mount("/", StaticFiles(directory=str(config.STATIC_DIR), html=True), name="static")
