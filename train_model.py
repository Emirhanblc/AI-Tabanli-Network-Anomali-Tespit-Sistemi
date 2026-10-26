"""Sentetik ağ trafiği üretip IDS karar modeli eğitir."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from numpy.random import Generator
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

ROOT_DIR = Path(__file__).resolve().parent
FEATURE_COLUMNS = ["packet_size", "src_port", "dst_port", "packet_rate"]
LABEL_COLUMN = "is_anomaly"
NORMAL_DST_PORTS = np.array([53, 80, 123, 443, 8080, 22])
NORMAL_DST_PORT_WEIGHTS = np.array([0.15, 0.34, 0.05, 0.36, 0.05, 0.05])


def ensure_directories(root: Path) -> tuple[Path, Path]:
    """Proje kökünde dataset/ ve models/ klasörlerini hazırlar."""
    dataset_dir = root / "dataset"
    models_dir = root / "models"

    print("[1/4] Dizinler kontrol ediliyor...")
    for directory in (dataset_dir, models_dir):
        relative = directory.relative_to(root)
        if directory.is_dir():
            print(f"      Mevcut: {relative}/")
            continue
        directory.mkdir(parents=True, exist_ok=True)
        print(f"      Oluşturuldu: {relative}/")

    return dataset_dir, models_dir


def _build_frame(
    packet_size: np.ndarray,
    src_port: np.ndarray,
    dst_port: np.ndarray,
    packet_rate: np.ndarray,
    is_anomaly: int,
) -> pd.DataFrame:
    """Özellik dizilerini tek bir etiketli tabloya çevirir."""
    return pd.DataFrame(
        {
            "packet_size": packet_size.astype(int),
            "src_port": np.clip(src_port, 1, 65535).astype(int),
            "dst_port": np.clip(dst_port, 1, 65535).astype(int),
            "packet_rate": np.round(packet_rate, 2),
            LABEL_COLUMN: is_anomaly,
        }
    )


def generate_normal_traffic(rng: Generator, n_rows: int) -> pd.DataFrame:
    """Gündelik istemci trafiğini andıran satırlar üretir."""
    packet_size = rng.integers(64, 1501, size=n_rows)
    src_port = rng.integers(49152, 65536, size=n_rows)
    dst_port = rng.choice(NORMAL_DST_PORTS, size=n_rows, p=NORMAL_DST_PORT_WEIGHTS)
    packet_rate = rng.uniform(0.5, 40.0, size=n_rows)
    return _build_frame(packet_size, src_port, dst_port, packet_rate, is_anomaly=0)


def generate_anomalous_traffic(rng: Generator, n_rows: int) -> pd.DataFrame:
    """Tarama, taşkın ve kaba kuvvet örüntülerine benzeyen sentetik satırlar üretir."""
    n_scan = n_rows // 3
    n_flood = n_rows // 3
    n_brute = n_rows - n_scan - n_flood

    scan = _build_frame(
        packet_size=rng.integers(40, 90, size=n_scan),
        src_port=rng.integers(40000, 41000, size=n_scan),
        dst_port=rng.integers(1, 65536, size=n_scan),
        packet_rate=rng.uniform(300.0, 2500.0, size=n_scan),
        is_anomaly=1,
    )
    flood = _build_frame(
        packet_size=rng.integers(40, 160, size=n_flood),
        src_port=rng.integers(1024, 65536, size=n_flood),
        dst_port=rng.choice(np.array([80, 443]), size=n_flood),
        packet_rate=rng.uniform(4000.0, 20000.0, size=n_flood),
        is_anomaly=1,
    )
    brute = _build_frame(
        packet_size=rng.integers(60, 220, size=n_brute),
        src_port=rng.integers(1024, 65536, size=n_brute),
        dst_port=np.full(n_brute, 22),
        packet_rate=rng.uniform(80.0, 400.0, size=n_brute),
        is_anomaly=1,
    )
    return pd.concat([scan, flood, brute], ignore_index=True)


def generate_data(
    n_rows: int = 1000,
    anomaly_ratio: float = 0.2,
    random_state: int = 42,
) -> pd.DataFrame:
    """Normal ve anomal satırları karıştırıp tek bir DataFrame döndürür."""
    if n_rows <= 0:
        raise ValueError("n_rows sıfırdan büyük olmalıdır.")
    if not 0 < anomaly_ratio < 1:
        raise ValueError("anomaly_ratio 0 ile 1 arasında olmalıdır.")

    rng = np.random.default_rng(random_state)
    n_anomaly = int(round(n_rows * anomaly_ratio))
    n_normal = n_rows - n_anomaly

    print(
        f"[2/4] Sentetik veri üretiliyor ({n_rows} satır, "
        f"anomali oranı %{anomaly_ratio * 100:.0f})..."
    )
    normal = generate_normal_traffic(rng, n_normal)
    anomaly = generate_anomalous_traffic(rng, n_anomaly)
    dataset = pd.concat([normal, anomaly], ignore_index=True)
    dataset = dataset.sample(frac=1, random_state=random_state).reset_index(drop=True)

    anomaly_count = int(dataset[LABEL_COLUMN].sum())
    print(f"      Normal: {n_rows - anomaly_count} | Anomali: {anomaly_count}")
    return dataset


def save_dataset(df: pd.DataFrame, path: Path) -> None:
    """Veri setini CSV olarak kaydeder."""
    df.to_csv(path, index=False)
    print(f"      Kaydedildi: {path}")


def train_model(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[RandomForestClassifier, float, str]:
    """RandomForestClassifier eğitir; doğruluk ve sınıflandırma raporunu döndürür."""
    print(
        f"[3/4] RandomForestClassifier eğitiliyor "
        f"(test oranı %{test_size * 100:.0f}, random_state={random_state})..."
    )
    features = df[FEATURE_COLUMNS]
    labels = df[LABEL_COLUMN]
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )

    model = RandomForestClassifier(n_estimators=100, random_state=random_state)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    accuracy = float(accuracy_score(y_test, predictions))
    report = classification_report(
        y_test,
        predictions,
        target_names=["Normal (0)", "Anomali (1)"],
        digits=4,
    )
    print(f"      Eğitim: {len(x_train)} satır | Test: {len(x_test)} satır")
    return model, accuracy, report


def save_model(model: RandomForestClassifier, path: Path) -> None:
    """Eğitilmiş modeli joblib ile diske yazar."""
    joblib.dump(model, path)
    print(f"      Model kaydedildi: {path}")


def main() -> None:
    """Dizinleri hazırlar, sentetik veriyi üretir, modeli eğitir ve kaydeder."""
    dataset_dir, models_dir = ensure_directories(ROOT_DIR)

    dataset = generate_data()
    save_dataset(dataset, dataset_dir / "synthetic_traffic.csv")

    model, accuracy, report = train_model(dataset)

    print("[4/4] Değerlendirme")
    print(f"      Doğruluk (accuracy): {accuracy:.4f}")
    print(report)
    save_model(model, models_dir / "ids_model.joblib")
    print("      İşlem tamamlandı.")


if __name__ == "__main__":
    main()
