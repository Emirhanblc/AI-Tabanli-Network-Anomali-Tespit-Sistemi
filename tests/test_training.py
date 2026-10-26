import pandas as pd

from shared.features import LABELS, MODEL_FEATURES
from training.train import map_label, train


def test_cicids_label_mapping() -> None:
    assert map_label("BENIGN") == "Temiz"
    assert map_label("DDoS") == "DDoS"
    assert map_label("FTP-Patator") == "Brute Force"
    assert map_label("Web Attack � Brute Force") == "Brute Force"
    assert map_label("PortScan") == "Port Scan"
    assert map_label("Bot") is None


def test_model_can_be_trained_and_predict_all_contract_fields() -> None:
    rows = []
    for label_index, label in enumerate(LABELS):
        for index in range(20):
            rows.append(
                {
                    "dst_port": 20 + label_index * 1000 + index,
                    "packet_size": 60 + label_index * 400 + index,
                    "send_rate": 1 + label_index * 100 + index,
                    "syn": label_index % 2,
                    "ack": (label_index + 1) % 2,
                    "label": label,
                }
            )
    data = pd.DataFrame(rows)
    model, metrics = train(data, seed=42)

    assert metrics["rows"] == 80
    assert list(model.feature_names_in_) == list(MODEL_FEATURES)
    assert model.predict(data[list(MODEL_FEATURES)].iloc[:1])[0] in LABELS
