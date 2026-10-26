"""Eğitim ve canlı çıkarım arasındaki özellik sözleşmesi."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pandas as pd

LABELS = ("Temiz", "DDoS", "Brute Force", "Port Scan")
MODEL_FEATURES = ("dst_port", "packet_size", "send_rate", "syn", "ack")


def model_frame(payload: Mapping[str, Any]) -> pd.DataFrame:
    """Tek bir API/dinleyici kaydını modelin beklediği sıraya çevirir."""
    row = {
        "dst_port": int(payload["dst_port"]),
        "packet_size": float(payload["packet_size"]),
        "send_rate": float(payload["send_rate"]),
        "syn": int(bool(payload["syn"])),
        "ack": int(bool(payload["ack"])),
    }
    return pd.DataFrame([row], columns=MODEL_FEATURES)
