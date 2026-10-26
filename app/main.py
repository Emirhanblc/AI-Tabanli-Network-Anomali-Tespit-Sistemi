"""FastAPI tabanlı IDS karar ve kayıt servisi."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

import joblib
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.models import Alert, Traffic
from app.schemas import AlertResponse, PacketFeatures, PredictionResponse, TrafficResponse
from shared.features import LABELS, model_frame

MODEL_PATH = Path(os.getenv("MODEL_PATH", "artifacts/model.pkl"))


def get_session():
    with SessionLocal() as session:
        yield session


def database_ready() -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.model = None
    app.state.model_error = None
    try:
        app.state.model = joblib.load(MODEL_PATH)
    except Exception as exc:
        app.state.model_error = f"{type(exc).__name__}: model yüklenemedi"
    try:
        Base.metadata.create_all(engine)
    except SQLAlchemyError:
        pass
    yield


app = FastAPI(title="Yapay Zeka Destekli IDS", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, object]:
    model_ok = app.state.model is not None
    db_ok = database_ready()
    return {
        "status": "ready" if model_ok and db_ok else "not_ready",
        "ready": model_ok and db_ok,
        "model": "loaded" if model_ok else "not_loaded",
        "database": "reachable" if db_ok else "unreachable",
        "detail": app.state.model_error,
    }


@app.post("/predict", response_model=PredictionResponse)
def predict(packet: PacketFeatures, session: Session = Depends(get_session)) -> PredictionResponse:
    if app.state.model is None:
        raise HTTPException(status_code=503, detail="Model hazır değil.")
    try:
        label = str(app.state.model.predict(model_frame(packet.model_dump()))[0])
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Model çıkarımı başarısız.") from exc
    if label not in LABELS:
        raise HTTPException(status_code=500, detail="Model bilinmeyen sınıf döndürdü.")
    verdict: Literal["Temiz", "Tehdit"] = "Temiz" if label == "Temiz" else "Tehdit"
    traffic = Traffic(
        captured_at=packet.timestamp,
        protocol=packet.protocol,
        src_ip=str(packet.src_ip),
        dst_ip=str(packet.dst_ip),
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        packet_size=packet.packet_size,
        send_rate=packet.send_rate,
        syn=packet.syn,
        ack=packet.ack,
        verdict=verdict,
        label=label,
    )
    try:
        session.add(traffic)
        session.flush()
        if verdict == "Tehdit":
            session.add(
                Alert(
                    traffic_id=traffic.id,
                    captured_at=packet.timestamp,
                    label=label,
                    src_ip=str(packet.src_ip),
                    dst_ip=str(packet.dst_ip),
                    dst_port=packet.dst_port,
                )
            )
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(status_code=503, detail="Veritabanı hazır değil.") from exc
    return PredictionResponse(verdict=verdict, label=label, id=traffic.id)


@app.get("/traffic", response_model=list[TrafficResponse])
def traffic(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    verdict: Literal["Temiz", "Tehdit"] | None = None,
    session: Session = Depends(get_session),
) -> list[Traffic]:
    statement = select(Traffic)
    if verdict is not None:
        statement = statement.where(Traffic.verdict == verdict)
    return list(session.scalars(statement.order_by(Traffic.captured_at.desc()).limit(limit)))


@app.get("/alerts", response_model=list[AlertResponse])
def alerts(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    session: Session = Depends(get_session),
) -> list[Alert]:
    statement = select(Alert).order_by(Alert.captured_at.desc()).limit(limit)
    return list(session.scalars(statement))
