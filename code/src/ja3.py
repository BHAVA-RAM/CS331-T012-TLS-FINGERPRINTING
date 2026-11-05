#!/usr/bin/env python3
"""Calculate JA3 fingerprints from TLS ClientHello messages in a PCAP."""

import argparse
import hashlib
from scapy.all import IP, IPv6, load_layer, sniff
from scapy.sessions import TCPSession

# Enable Scapy's TLS packet dissector.
load_layer("tls")

from scapy.layers.tls.handshake import TLSClientHello


# GREASE values defined by RFC 8701.
# These reserved values help TLS implementations exercise extensibility.
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def get_endpoints(packet):
    """Return the packet's source and destination IP addresses."""
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return "unknown", "unknown"


def without_grease(values):
    """Remove GREASE values while preserving the remaining order."""
    return [
        int(value)
        for value in values
        if int(value) not in GREASE_VALUES
    ]


def hyphen_join(values):
    """Represent integer values as a hyphen-separated string."""
    return "-".join(str(value) for value in values)


def build_ja3_string(hello):
    """Build the five comma-separated fields used by JA3."""

    # Field 1: ClientHello legacy version.
    version = int(hello.version)

    # Field 2: Cipher suites, with GREASE values removed.
    ciphers = without_grease(
        getattr(hello, "ciphers", None) or []
    )

    extensions = getattr(hello, "ext", None) or []

    # Field 3: Extension IDs, preserving their original order.
    extension_ids = without_grease(
        [
            int(extension.type)
            for extension in extensions
            if getattr(extension, "type", None) is not None
        ]
    )

    supported_groups = []
    point_formats = []

    for extension in extensions:
        extension_type = getattr(extension, "type", None)

        # Field 4: Supported groups from extension type 10.
        if extension_type == 10:
            supported_groups = without_grease(
                getattr(extension, "groups", None) or []
            )

        # Field 5: EC point formats from extension type 11.
        elif extension_type == 11:
            point_formats = [
                int(value)
                for value in (
                    getattr(extension, "ecpl", None) or []
                )
            ]

    # JA3 requires five fields separated by commas.
    # Lists within each field are separated by hyphens.
    ja3_parts = [
        str(version),
        hyphen_join(ciphers),
        hyphen_join(extension_ids),
        hyphen_join(supported_groups),
        hyphen_join(point_formats),
    ]

    return ",".join(ja3_parts)


def calculate_ja3(hello):
    """Return the JA3 string and its hexadecimal MD5 digest."""
    ja3_string = build_ja3_string(hello)

    # MD5 is used for compatibility with the JA3 fingerprint format,
    # not as a security mechanism.
    fingerprint = hashlib.md5(
        ja3_string.encode("ascii")
    ).hexdigest()

    return ja3_string, fingerprint


def main():
    parser = argparse.ArgumentParser(
        description="Calculate JA3 fingerprints from a PCAP."
    )

    parser.add_argument(
    "pcap",
    help="Path to the PCAP file to calculate JA3 fingerprints from",
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
        if not packet.haslayer(TLSClientHello):
            continue

        hello_count += 1
        source, destination = get_endpoints(packet)

        ja3_string, fingerprint = calculate_ja3(
            packet[TLSClientHello]
        )

        print(f"\nClientHello #{hello_count}")
        print(f"  Source:       {source}")
        print(f"  Destination:  {destination}")
        print(f"  JA3 string:   {ja3_string}")
        print(f"  JA3 MD5:      {fingerprint}")

    print(f"\nClientHello messages processed: {hello_count}")

    if hello_count == 0:
        print(
            "No ClientHello messages were parsed. "
            "Check the PCAP and TCP reassembly if necessary."
        )


if __name__ == "__main__":
    main()
