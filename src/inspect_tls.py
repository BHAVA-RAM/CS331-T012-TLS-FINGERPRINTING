#!/usr/bin/env python3
"""Inspect TLS ClientHello and ServerHello messages in a PCAP file."""

import argparse

from scapy.all import IP, IPv6, load_layer, sniff
from scapy.sessions import TCPSession

# Enable Scapy's TLS dissector before importing TLS message classes.
load_layer("tls")

from scapy.layers.tls.handshake import (
    TLSClientHello,
    TLSServerHello,
)

def get_endpoints(packet):
    """Return source and destination IP addresses."""
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return "unknown", "unknown"


def get_extension_ids(hello):
    """Return extension type numbers in their original order."""
    extensions = getattr(hello, "ext", None) or []

    return [
        int(extension.type)
        for extension in extensions
        if getattr(extension, "type", None) is not None
    ]


def inspect_client_hello(packet, hello, number):
    """Print the fields needed to understand a JA3 fingerprint."""
    source, destination = get_endpoints(packet)

    ciphers = [
        int(cipher)
        for cipher in (getattr(hello, "ciphers", None) or [])
    ]

    extensions = getattr(hello, "ext", None) or []
    extension_ids = get_extension_ids(hello)

    supported_groups = []
    point_formats = []

    for extension in extensions:
        extension_type = getattr(extension, "type", None)

        # Extension 10: supported groups (formerly elliptic curves).
        if extension_type == 10:
            supported_groups.extend(
                int(group)
                for group in (getattr(extension, "groups", None) or [])
            )

        # Extension 11: supported elliptic-curve point formats.
        elif extension_type == 11:
            point_formats.extend(
                int(value)
                for value in (getattr(extension, "ecpl", None) or [])
            )

    print(f"\nClientHello #{number}")
    print(f"  Source:              {source}")
    print(f"  Destination:         {destination}")
    print(f"  Legacy version:      {hello.version}")
    print(f"  Cipher suites:       {ciphers}")
    print(f"  Extension IDs:       {extension_ids}")
    print(f"  Supported groups:    {supported_groups}")
    print(f"  EC point formats:    {point_formats}")


def inspect_server_hello(packet, hello, number):
    """Print basic ServerHello fields for later JA3S work."""
    source, destination = get_endpoints(packet)

    print(f"\nServerHello #{number}")
    print(f"  Source:              {source}")
    print(f"  Destination:         {destination}")
    print(f"  Legacy version:      {hello.version}")
    print(f"  Selected cipher:     {hello.cipher}")
    print(f"  Extension IDs:       {get_extension_ids(hello)}")


def main():
    parser = argparse.ArgumentParser(
        description="Inspect TLS handshakes in a PCAP file."
    )
    parser.add_argument(
    "pcap",
    help="Path to the PCAP file to inspect",
)
    args = parser.parse_args()

    packets = sniff(
    offline=args.pcap,
    session=TCPSession,
    store=True,
)

    client_count = 0
    server_count = 0

    print(f"Capture file: {args.pcap}")
    print("Packets returned by Scapy (TCP session mode): "f"{len(packets)}")

    for packet in packets:
        if packet.haslayer(TLSClientHello):
            client_count += 1
            inspect_client_hello(
                packet, packet[TLSClientHello], client_count
            )

        if packet.haslayer(TLSServerHello):
            server_count += 1
            inspect_server_hello(
                packet, packet[TLSServerHello], server_count
            )

    print("\n--- Summary ---")
    print(f"ClientHello messages parsed: {client_count}")
    print(f"ServerHello messages parsed: {server_count}")

    if client_count == 0 or server_count == 0:
        print(
            "One or both handshake types were not parsed. "
            "If Wireshark displays them, tell me; we can investigate "
            "Scapy's packet decoding or TCP reassembly."
        )


if __name__ == "__main__":
    main()
