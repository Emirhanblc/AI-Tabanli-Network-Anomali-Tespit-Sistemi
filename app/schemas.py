"""HTTP istek ve yanıt şemaları."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class PacketFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    protocol: Literal["TCP", "UDP"]
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    packet_size: int = Field(gt=0, le=65535)
    send_rate: float = Field(ge=0)
    syn: bool
    ack: bool


class PredictionResponse(BaseModel):
    verdict: Literal["Temiz", "Tehdit"]
    label: Literal["Temiz", "DDoS", "Brute Force", "Port Scan"]
    id: int


class TrafficResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    captured_at: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_size: int
    send_rate: float
    syn: bool
    ack: bool
    verdict: str
    label: str


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    traffic_id: int
    captured_at: datetime
    label: str
    src_ip: str
    dst_ip: str
    dst_port: int
