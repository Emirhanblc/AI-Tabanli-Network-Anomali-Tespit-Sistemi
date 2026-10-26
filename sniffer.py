"""Seçilen arayüzde yükü okumadan TCP/UDP başlıklarından API girdisi üretir."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from time import sleep
from time import time
from typing import Callable

from scapy.all import IP, TCP, UDP, conf, sniff
from scapy.packet import Packet

RATE_WINDOW_SECONDS = 1.0


class PacketRateTracker:
    """Aynı kaynak IP için son penceredeki paket sayısını tutar."""

    def __init__(self, window_seconds: float = RATE_WINDOW_SECONDS) -> None:
        if window_seconds <= 0:
            raise ValueError("Pencere süresi sıfırdan büyük olmalıdır.")
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def observe(self, src_ip: str, now: float) -> float:
        """Yeni paketi kaydeder ve penceredeki paket sayısını döndürür."""
        events = self._events[src_ip]
        events.append(now)
        self._expire(events, now)
        if len(self._events) > 4096:
            self._prune(now)
        return len(events) / self.window_seconds

    def _expire(self, events: deque[float], now: float) -> None:
        """Pencere dışındaki zaman damgalarını atar."""
        cutoff = now - self.window_seconds
        while events and events[0] < cutoff:
            events.popleft()

    def _prune(self, now: float) -> None:
        """Artık paket göndermeyen kaynakların sayaçlarını siler."""
        cutoff = now - self.window_seconds
        stale = [ip for ip, events in self._events.items() if not events or events[-1] < cutoff]
        for ip in stale:
            del self._events[ip]


@dataclass
class TrafficCounters:
    processed: int = 0
    ignored: int = 0
    send_errors: int = 0


def extract_features(
    packet: Packet,
    tracker: PacketRateTracker,
    observed_at: float | None = None,
) -> dict[str, object] | None:
    """IP + TCP/UDP paketinden API sözleşmesini üretir."""
    if not packet.haslayer(IP):
        return None
    if packet.haslayer(TCP):
        transport = packet[TCP]
        protocol = "TCP"
        syn = bool(int(transport.flags) & 0x02)
        ack = bool(int(transport.flags) & 0x10)
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        protocol = "UDP"
        syn = ack = False
    else:
        return None

    ip_layer = packet[IP]
    now = observed_at if observed_at is not None else time()
    raw_size = ip_layer.len
    packet_size = int(raw_size) if raw_size is not None else len(bytes(ip_layer))
    return {
        "timestamp": datetime.fromtimestamp(now, tz=UTC).isoformat(),
        "protocol": protocol,
        "src_ip": str(ip_layer.src),
        "dst_ip": str(ip_layer.dst),
        "packet_size": packet_size,
        "src_port": int(transport.sport),
        "dst_port": int(transport.dport),
        "send_rate": tracker.observe(str(ip_layer.src), now),
        "syn": syn,
        "ack": ack,
    }


def format_features(features: dict[str, object]) -> str:
    """Özellikleri tek satırlık JSON metnine çevirir."""
    return json.dumps(features, ensure_ascii=False)


def send_http(payload: dict[str, object], api_url: str, retries: int = 2) -> None:
    """Özellik kaydını kısa zaman aşımı ve sınırlı tekrar ile API'ye gönderir."""
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/predict",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=1.5) as response:
                if response.status != 200:
                    raise RuntimeError(f"API HTTP {response.status}")
                return
        except (urllib.error.URLError, TimeoutError, RuntimeError):
            if attempt == retries:
                raise
            sleep(0.15 * (attempt + 1))


def build_handler(
    tracker: PacketRateTracker,
    counters: TrafficCounters | None = None,
    emit: Callable[[dict[str, object]], None] | None = None,
) -> Callable[[Packet], None]:
    """Her yakalanan paket için özelliği seçilen hedefe iletir."""
    counters = counters or TrafficCounters()
    emit = emit or (lambda payload: print(format_features(payload), flush=True))

    def handle(packet: Packet) -> None:
        features = extract_features(packet, tracker)
        if features is None:
            counters.ignored += 1
            return
        counters.processed += 1
        try:
            emit(features)
        except Exception as exc:
            counters.send_errors += 1
            print(f"Gönderim hatası: {type(exc).__name__}", file=sys.stderr, flush=True)

    return handle


def parse_args() -> argparse.Namespace:
    """Komut satırından dinlenecek arayüzü okur."""
    parser = argparse.ArgumentParser(
        description="Canlı TCP/UDP trafiğinden IDS model girdisi üretir."
    )
    parser.add_argument(
        "--iface",
        default=os.getenv("SNIFFER_INTERFACE"),
        help="Dinlenecek ağ arayüzü. Verilmezse Scapy varsayılan arayüzü kullanır.",
    )
    parser.add_argument(
        "--output",
        choices=("stdout", "http"),
        default=os.getenv("SNIFFER_OUTPUT", "stdout"),
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("IDS_API_URL", "http://127.0.0.1:8000"),
    )
    return parser.parse_args()


def run_sniffer(iface: str | None, output: str = "stdout", api_url: str = "") -> None:
    """Ctrl+C gelene kadar seçilen arayüzü dinler."""
    conf.verb = 0
    tracker = PacketRateTracker()
    counters = TrafficCounters()
    emit: Callable[[dict[str, object]], None]
    if output == "http":
        emit = lambda payload: send_http(payload, api_url)
    else:
        emit = lambda payload: print(format_features(payload), flush=True)
    target = iface or "varsayılan arayüz"
    print(f"Dinleme başladı ({target}, {output}).", file=sys.stderr, flush=True)
    try:
        sniff(
            iface=iface,
            filter="ip",
            prn=build_handler(tracker, counters, emit),
            store=False,
        )
    except KeyboardInterrupt:
        pass
    finally:
        print(
            f"Dinleme durdu: işlenen={counters.processed}, "
            f"yok_sayılan={counters.ignored}, hata={counters.send_errors}",
            file=sys.stderr,
            flush=True,
        )


def main() -> None:
    """Argümanları alır ve dinleyiciyi çalıştırır."""
    args = parse_args()
    run_sniffer(args.iface, args.output, args.api_url)


if __name__ == "__main__":
    main()
