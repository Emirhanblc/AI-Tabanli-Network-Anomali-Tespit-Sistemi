"""CICIDS2017 MachineLearningCSV paketini resmi kaynaktan indirir."""

from __future__ import annotations

import argparse
import shutil
import urllib.request
import zipfile
from pathlib import Path

DEFAULT_URL = (
    "https://www.unb.ca/cic/datasets/ids-2017.html"
)
DIRECT_URL = (
    "http://205.174.165.80/CICDataset/CIC-IDS-2017/"
    "Dataset/MachineLearningCSV.zip"
)
PARQUET_BASE = (
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/"
    "refs%2Fconvert%2Fparquet/machine_learning/train"
)


def download(url: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / "MachineLearningCSV.zip"
    if not archive.exists():
        partial = archive.with_suffix(".zip.part")
        request = urllib.request.Request(url, headers={"User-Agent": "IDS-lab/1.0"})
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as target:
            shutil.copyfileobj(response, target)
        partial.replace(archive)

    extract_dir = output_dir / "MachineLearningCVE"
    if not extract_dir.exists():
        with zipfile.ZipFile(archive) as package:
            package.extractall(output_dir)
    return extract_dir


def download_parquet(output_dir: Path) -> Path:
    """CICIDS2017'nin herkese açık Parquet aynasını indirir."""
    destination = output_dir / "MachineLearningCVE"
    destination.mkdir(parents=True, exist_ok=True)
    for index in range(8):
        target = destination / f"{index:04d}.parquet"
        if target.exists():
            continue
        partial = target.with_suffix(".parquet.part")
        request = urllib.request.Request(
            f"{PARQUET_BASE}/{index:04d}.parquet",
            headers={"User-Agent": "IDS-lab/1.0"},
        )
        with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as stream:
            shutil.copyfileobj(response, stream)
        partial.replace(target)
        print(f"İndirildi: {target}")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DIRECT_URL, help=f"ZIP adresi (bilgi: {DEFAULT_URL})")
    parser.add_argument("--output", type=Path, default=Path("data/raw"))
    parser.add_argument(
        "--source",
        choices=("parquet-mirror", "official-zip"),
        default="parquet-mirror",
        help="Resmi CSV'nin Parquet aynası, resmi sunucu erişilemiyorsa daha kararlıdır.",
    )
    args = parser.parse_args()
    if args.source == "official-zip":
        print(download(args.url, args.output))
    else:
        print(download_parquet(args.output))


if __name__ == "__main__":
    main()
