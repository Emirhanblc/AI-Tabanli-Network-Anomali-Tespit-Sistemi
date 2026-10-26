"""CICIDS2017 CSV dosyalarından dört sınıflı Random Forest modeli eğitir."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from shared.features import LABELS, MODEL_FEATURES

COLUMN_ALIASES = {
    "dst_port": ("destination port", "dst port", "dst_port"),
    "packet_size": ("average packet size", "packet length mean", "packet_size"),
    "send_rate": ("flow packets/s", "flow packets/s", "send_rate"),
    "syn": ("syn flag count", "syn"),
    "ack": ("ack flag count", "ack"),
    "label": ("label",),
}


def normalize_name(value: str) -> str:
    return " ".join(value.strip().lower().replace("_", " ").split())


def map_label(value: object) -> str | None:
    label = str(value).strip().lower().replace("�", "-").replace("–", "-")
    if label == "benign":
        return "Temiz"
    if "ddos" in label or label.startswith("dos ") or "heartbleed" in label:
        return "DDoS"
    if "patator" in label or "brute force" in label or "bruteforce" in label:
        return "Brute Force"
    if "portscan" in label or "port scan" in label:
        return "Port Scan"
    return None


def resolve_columns(columns: list[str]) -> dict[str, str]:
    normalized = {normalize_name(column): column for column in columns}
    resolved: dict[str, str] = {}
    for target, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if normalize_name(alias) in normalized:
                resolved[target] = normalized[normalize_name(alias)]
                break
        if target not in resolved:
            raise ValueError(f"Gerekli kolon bulunamadı: {target}")
    return resolved


def load_dataset(csv_dir: Path, max_per_class: int, seed: int) -> pd.DataFrame:
    files = sorted([*csv_dir.rglob("*.csv"), *csv_dir.rglob("*.parquet")])
    if not files:
        raise FileNotFoundError(f"CSV veya Parquet bulunamadı: {csv_dir}")

    frames: list[pd.DataFrame] = []
    for path in files:
        if path.suffix == ".parquet":
            import pyarrow.parquet as parquet

            available = parquet.ParquetFile(path).schema.names
        else:
            available = pd.read_csv(path, nrows=0, encoding_errors="replace").columns.tolist()
        columns = resolve_columns(available)
        usecols = list(dict.fromkeys(columns.values()))
        if path.suffix == ".parquet":
            chunks = [pd.read_parquet(path, columns=usecols)]
        else:
            chunks = pd.read_csv(
                path,
                usecols=usecols,
                chunksize=100_000,
                low_memory=False,
                encoding_errors="replace",
            )
        for chunk in chunks:
            chunk = chunk.rename(columns={source: target for target, source in columns.items()})
            chunk["label"] = chunk["label"].map(map_label)
            chunk = chunk.dropna(subset=["label"])
            if chunk.empty:
                continue
            chunk["syn"] = pd.to_numeric(chunk["syn"], errors="coerce").gt(0).astype(int)
            chunk["ack"] = pd.to_numeric(chunk["ack"], errors="coerce").gt(0).astype(int)
            for column in ("dst_port", "packet_size", "send_rate"):
                chunk[column] = pd.to_numeric(chunk[column], errors="coerce")
            selected = chunk[[*MODEL_FEATURES, "label"]]
            frames.extend(
                group.sample(n=min(len(group), max_per_class), random_state=seed)
                for _, group in selected.groupby("label", sort=False)
            )

    if not frames:
        raise ValueError("Desteklenen dört sınıfa ait kayıt bulunamadı.")
    data = pd.concat(frames, ignore_index=True).replace([np.inf, -np.inf], np.nan)
    sampled = [
        group.sample(n=min(len(group), max_per_class), random_state=seed)
        for _, group in data.groupby("label", sort=False)
    ]
    return pd.concat(sampled, ignore_index=True).sample(frac=1, random_state=seed)


def train(data: pd.DataFrame, seed: int) -> tuple[Pipeline, dict[str, object]]:
    x_train, x_test, y_train, y_test = train_test_split(
        data[list(MODEL_FEATURES)],
        data["label"],
        test_size=0.2,
        random_state=seed,
        stratify=data["label"],
    )
    model = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=250,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=seed,
                    min_samples_leaf=2,
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)
    predicted = model.predict(x_test)
    report = classification_report(
        y_test, predicted, labels=list(LABELS), output_dict=True, zero_division=0
    )
    metrics: dict[str, object] = {
        "created_at": datetime.now(UTC).isoformat(),
        "features": list(MODEL_FEATURES),
        "labels": list(LABELS),
        "rows": int(len(data)),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "accuracy": float(accuracy_score(y_test, predicted)),
        "classification_report": report,
        "confusion_matrix": confusion_matrix(y_test, predicted, labels=list(LABELS)).tolist(),
        "class_counts": {str(k): int(v) for k, v in data["label"].value_counts().items()},
        "seed": seed,
    }
    return model, metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/raw/MachineLearningCVE"))
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    parser.add_argument("--max-per-class", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    data = load_dataset(args.input, args.max_per_class, args.seed)
    model, metrics = train(data, args.seed)
    args.output.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output / "model.pkl")
    (args.output / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Model: {args.output / 'model.pkl'}")
    print(f"Doğruluk: {metrics['accuracy']:.4f}")


if __name__ == "__main__":
    main()
