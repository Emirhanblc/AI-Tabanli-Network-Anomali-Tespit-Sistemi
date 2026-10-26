from scapy.all import ICMP, IP, TCP, UDP

from sniffer import PacketRateTracker, TrafficCounters, build_handler, extract_features


def test_tcp_contract_and_flags() -> None:
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443, flags="SA")
    result = extract_features(packet, PacketRateTracker(), observed_at=100.0)

    assert result is not None
    assert set(result) == {
        "timestamp",
        "protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "packet_size",
        "send_rate",
        "syn",
        "ack",
    }
    assert result["protocol"] == "TCP"
    assert result["syn"] is True
    assert result["ack"] is True


def test_udp_has_no_flags_and_rate_uses_window() -> None:
    tracker = PacketRateTracker(window_seconds=2.0)
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5000)
    first = extract_features(packet, tracker, observed_at=10.0)
    second = extract_features(packet, tracker, observed_at=11.0)

    assert first and first["send_rate"] == 0.5
    assert second and second["send_rate"] == 1.0
    assert second["syn"] is False and second["ack"] is False


def test_other_protocol_is_counted_and_not_emitted() -> None:
    counters = TrafficCounters()
    emitted: list[dict[str, object]] = []
    handler = build_handler(PacketRateTracker(), counters, emitted.append)
    handler(IP() / ICMP())

    assert counters.ignored == 1
    assert emitted == []
