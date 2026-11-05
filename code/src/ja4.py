
import argparse
import hashlib

from scapy.all import IP, IPv6, load_layer, sniff
from scapy.layers.tls.handshake import TLSClientHello
from scapy.sessions import TCPSession


# TLS versions used by the JA4 specification.
TLS_VERSION_CODES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}


def is_grease(value):
    """Check whether a TLS value is a GREASE value."""
    value = int(value)

    return (
        (value & 0x0F0F) == 0x0A0A
        and (value >> 8) == (value & 0xFF)
    )


def without_grease(values):
    """Remove GREASE values while preserving the remaining order."""
    return [
        int(value)
        for value in values
        if not is_grease(value)
    ]


def get_extension_id(extension):
    """Return the numeric extension ID."""
    value = getattr(extension, "type", None)

    if value is None:
        raise ValueError("TLS extension is missing its numeric type.")

    return int(value)


def get_supported_version(hello, extensions):
    """
    Return the highest supported TLS version.

    JA4 uses the supported_versions extension when present.
    Otherwise, it uses the ClientHello legacy version.
    """
    supported_versions_extension = next(
        (ext for ext in extensions if get_extension_id(ext) == 43),
        None
    )

    if supported_versions_extension is not None:
        versions = getattr(
            supported_versions_extension,
            "versions",
            None
        )

        if versions is None:
            raise ValueError(
                "Could not parse ClientHello supported_versions extension."
            )

        versions = without_grease(versions)

        if not versions:
            return "00"

        selected_version = max(versions)

    else:
        selected_version = getattr(hello, "version", None)

        if selected_version is None:
            return "00"

        selected_version = int(selected_version)

    return TLS_VERSION_CODES.get(selected_version, "00")


def get_alpn_code(extensions):
    """
    Extract JA4's two-character ALPN representation.

    Only the first ALPN protocol is used.
    """
    alpn_extension = next(
        (ext for ext in extensions if get_extension_id(ext) == 16),
        None
    )

    if alpn_extension is None:
        return "00"

    protocols = getattr(alpn_extension, "protocols", [])

    if not protocols:
        return "00"

    first_protocol = protocols[0]

    # Scapy normally represents each protocol as a ProtocolName packet.
    if hasattr(first_protocol, "protocol"):
        first_protocol = first_protocol.protocol

    if isinstance(first_protocol, str):
        first_protocol = first_protocol.encode("ascii")

    if not isinstance(first_protocol, (bytes, bytearray)):
        raise ValueError("Could not decode the first ALPN protocol.")

    first_protocol = bytes(first_protocol)

    if not first_protocol:
        return "00"

    first_byte = first_protocol[0]
    last_byte = first_protocol[-1]

    def is_ascii_alphanumeric(value):
        return (
            0x30 <= value <= 0x39
            or 0x41 <= value <= 0x5A
            or 0x61 <= value <= 0x7A
        )

    if (
        is_ascii_alphanumeric(first_byte)
        and is_ascii_alphanumeric(last_byte)
    ):
        return (
            chr(first_byte).lower()
            + chr(last_byte).lower()
        )

    # If either end is non-alphanumeric, use the outer
    # characters of the protocol's hexadecimal representation.
    hexadecimal = first_protocol.hex()

    return hexadecimal[0] + hexadecimal[-1]


def get_signature_algorithms(extensions):
    """
    Extract signature algorithms from extension 13.

    Their original order is preserved for the JA4 extension hash.
    """
    algorithms = []

    for extension in extensions:
        if get_extension_id(extension) != 13:
            continue

        values = getattr(extension, "sig_algs", None)

        if values is None:
            continue

        algorithms.extend(without_grease(values))

    return algorithms


def calculate_sha256_prefix(value):
    """Return the first 12 lowercase characters of SHA-256."""
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:12]


def format_count(count):
    """Format a JA4 count using two characters, capped at 99."""
    return f"{min(count, 99):02d}"


def build_ja4_from_components(
    protocol,
    version,
    has_sni,
    ciphers,
    extension_ids,
    alpn,
    signature_algorithms
):
    """
    Construct a canonical JA4 fingerprint from parsed components.

    This function is independent of Scapy, which also makes
    the JA4 algorithm easy to validate with reference vectors.
    """

    if protocol not in ("t", "q", "d"):
        raise ValueError("Protocol must be 't', 'q', or 'd'.")

    # Remove GREASE from all relevant lists.
    clean_ciphers = without_grease(ciphers)
    clean_extensions = without_grease(extension_ids)
    clean_signatures = without_grease(signature_algorithms)

    # JA4_a: protocol, version, SNI, counts and ALPN.
    sni_code = "d" if has_sni else "i"

    part_a = (
        protocol
        + version
        + sni_code
        + format_count(len(clean_ciphers))
        + format_count(len(clean_extensions))
        + alpn
    )

    # JA4_b: sorted cipher suites, hashed with SHA-256.
    sorted_ciphers = sorted(clean_ciphers)

    if sorted_ciphers:
        cipher_input = ",".join(
            f"{cipher:04x}"
            for cipher in sorted_ciphers
        )

        part_b = calculate_sha256_prefix(cipher_input)
    else:
        part_b = "000000000000"

    # JA4_c: sorted extensions, excluding SNI and ALPN.
    sorted_extensions = sorted(
        extension
        for extension in clean_extensions
        if extension not in (0, 16)
    )

    extension_input = ",".join(
        f"{extension:04x}"
        for extension in sorted_extensions
    )

    # Signature algorithms are appended in their original order.
    if clean_signatures:
        signature_input = ",".join(
            f"{algorithm:04x}"
            for algorithm in clean_signatures
        )

        extension_input += "_" + signature_input

    if sorted_extensions:
        part_c = calculate_sha256_prefix(extension_input)
    else:
        part_c = "000000000000"

    return f"{part_a}_{part_b}_{part_c}"


def calculate_ja4(hello, protocol="t"):
    """
    Calculate the JA4 fingerprint from a Scapy TLSClientHello.

    Current project captures use TLS over TCP, represented by 't'.
    """
    extensions = getattr(hello, "ext", None) or []

    extension_ids = [
        get_extension_id(extension)
        for extension in extensions
    ]

    ciphers = getattr(hello, "ciphers", None) or []

    version = get_supported_version(hello, extensions)

    has_sni = 0 in extension_ids

    alpn = get_alpn_code(extensions)

    signature_algorithms = get_signature_algorithms(extensions)

    return build_ja4_from_components(
        protocol=protocol,
        version=version,
        has_sni=has_sni,
        ciphers=ciphers,
        extension_ids=extension_ids,
        alpn=alpn,
        signature_algorithms=signature_algorithms
    )


def get_endpoints(packet):
    """Return source and destination IP addresses."""

    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return "Unknown", "Unknown"


def process_capture(capture_file):
    """Extract ClientHello messages and print their JA4 fingerprints."""

    load_layer("tls")

    packets = sniff(
        offline=str(capture_file),
        session=TCPSession,
        store=True
    )

    print(f"Capture file: {capture_file}")
    print(f"Total packets: {len(packets)}")

    client_hello_count = 0

    for packet in packets:

        if TLSClientHello not in packet:
            continue

        hello = packet[TLSClientHello]

        try:
            ja4_fingerprint = calculate_ja4(hello)
        except (TypeError, ValueError) as error:
            print(f"\nCould not calculate JA4: {error}")
            continue

        client_hello_count += 1

        source, destination = get_endpoints(packet)

        print(f"\nClientHello #{client_hello_count}")
        print(f"  Source:      {source}")
        print(f"  Destination: {destination}")
        print(f"  JA4:         {ja4_fingerprint}")

    print(f"\nClientHello messages fingerprinted: {client_hello_count}")


def main():

    parser = argparse.ArgumentParser(
        description="Calculate JA4 client fingerprints from a PCAP."
    )

    parser.add_argument(
        "pcap",
        help="Path to the input PCAP or PCAPNG file"
    )

    args = parser.parse_args()

    from pathlib import Path

    capture_file = Path(args.pcap)

    if not capture_file.is_file():
        parser.error(f"Capture file not found: {capture_file}")

    try:
        process_capture(capture_file)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
