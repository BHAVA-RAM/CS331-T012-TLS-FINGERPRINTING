#!/usr/bin/env python3
"""Calculate JA3S fingerprints from TLS ServerHello messages."""

import argparse
import hashlib
from scapy.all import IP, IPv6, load_layer, sniff
from scapy.sessions import TCPSession

# Explicitly enable Scapy's TLS dissector.
load_layer("tls")

from scapy.layers.tls.handshake import TLSServerHello


GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def get_endpoints(packet):
    """Return source and destination IP addresses."""

    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return "unknown", "unknown"


def without_grease(values):
    """Remove GREASE values without changing the remaining order."""

    return [
        int(value)
        for value in values
        if int(value) not in GREASE_VALUES
    ]


def build_ja3s_string(hello):
    """Build the JA3S string from a TLS ServerHello."""

    # Field 1: ServerHello legacy version.
    version = int(hello.version)

    # Field 2: The single cipher suite selected by the server.
    cipher = int(hello.cipher)

    # Field 3: ServerHello extension IDs, in their original order.
    extensions = getattr(hello, "ext", None) or []

    extension_ids = without_grease([
        int(extension.type)
        for extension in extensions
        if getattr(extension, "type", None) is not None
    ])

    extension_string = "-".join(
        str(value) for value in extension_ids
    )

    return f"{version},{cipher},{extension_string}"


def calculate_ja3s(hello):
    """Return the JA3S string and its MD5 digest."""

    ja3s_string = build_ja3s_string(hello)

    fingerprint = hashlib.md5(
        ja3s_string.encode("ascii")
    ).hexdigest()

    return ja3s_string, fingerprint


def main():
    parser = argparse.ArgumentParser(
        description="Calculate JA3S fingerprints from a PCAP."
    )

    parser.add_argument(
        "pcap",
        help="Path to a PCAP file",
    )

    args = parser.parse_args()
    packets = sniff(
    offline=args.pcap,
    session=TCPSession,
    store=True,
)

    print(f"Capture file: {args.pcap}")
    print(f"Total packets: {len(packets)}")

    hello_count = 0

    for packet in packets:
        if not packet.haslayer(TLSServerHello):
            continue

        hello_count += 1
        source, destination = get_endpoints(packet)

        ja3s_string, fingerprint = calculate_ja3s(
            packet[TLSServerHello]
        )

        print(f"\nServerHello #{hello_count}")
        print(f"  Source:       {source}")
        print(f"  Destination:  {destination}")
        print(f"  JA3S string:  {ja3s_string}")
        print(f"  JA3S MD5:     {fingerprint}")

    print(f"\nServerHello messages processed: {hello_count}")

    if hello_count == 0:
        print("No ServerHello messages were parsed.")


if __name__ == "__main__":
    main()
