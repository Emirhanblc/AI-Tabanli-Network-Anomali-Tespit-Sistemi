from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import Alert, Traffic


class DummyModel:
    def __init__(self, label: str) -> None:
        self.label = label

    def predict(self, frame):
        return [self.label]


@pytest.fixture()
def client() -> Iterator[TestClient]:
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as test_client:
        yield test_client


def packet() -> dict[str, object]:
    return {
        "timestamp": "2026-10-26T10:00:00Z",
        "protocol": "TCP",
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.20",
        "src_port": 50000,
        "dst_port": 22,
        "packet_size": 60,
        "send_rate": 15.0,
        "syn": True,
        "ack": False,
    }


def test_health_reports_missing_model(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["ready"] is False
    assert response.json()["database"] == "reachable"


def test_invalid_request_is_422_and_not_stored(client: TestClient) -> None:
    app.state.model = DummyModel("Temiz")
    payload = packet()
    del payload["src_ip"]
    response = client.post("/predict", json=payload)

    assert response.status_code == 422
    with SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(Traffic)) == 0


def test_threat_creates_traffic_and_alert(client: TestClient) -> None:
    app.state.model = DummyModel("Port Scan")
    response = client.post("/predict", json=packet())

    assert response.status_code == 200
    assert response.json()["verdict"] == "Tehdit"
    assert len(client.get("/traffic").json()) == 1
    assert len(client.get("/alerts").json()) == 1


def test_clean_filter_and_limit_validation(client: TestClient) -> None:
    app.state.model = DummyModel("Temiz")
    client.post("/predict", json=packet())

    rows = client.get("/traffic?verdict=Temiz&limit=1")
    assert rows.status_code == 200 and len(rows.json()) == 1
    assert client.get("/traffic?limit=501").status_code == 422
    assert client.get("/alerts").json() == []
