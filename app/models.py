"""SQLAlchemy trafik ve uyarı tabloları."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Traffic(Base):
    __tablename__ = "traffic"

    id: Mapped[int] = mapped_column(primary_key=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    protocol: Mapped[str] = mapped_column(String(3))
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    packet_size: Mapped[int] = mapped_column(Integer)
    send_rate: Mapped[float] = mapped_column(Float)
    syn: Mapped[bool] = mapped_column(Boolean)
    ack: Mapped[bool] = mapped_column(Boolean)
    verdict: Mapped[str] = mapped_column(String(6), index=True)
    label: Mapped[str] = mapped_column(String(32), index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    traffic_id: Mapped[int] = mapped_column(ForeignKey("traffic.id"), unique=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    label: Mapped[str] = mapped_column(String(32), index=True)
    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)
