
import argparse
import os
import socket
import struct


# TLS record and handshake constants.
TLS_HANDSHAKE = 0x16
TLS_RECORD_VERSION = 0x0301
TLS_LEGACY_VERSION = 0x0303
CLIENT_HELLO = 0x01


def uint16(value):
    """Encode an integer as a two-byte network-order value."""
    return struct.pack("!H", value)


def encode_extension(extension_type, data):
    """Encode a TLS extension with its type and length."""
    return uint16(extension_type) + uint16(len(data)) + data


def build_sni_extension(host):
    """Construct the Server Name Indication extension."""
    hostname = host.encode("idna")

    server_name = (
        b"\x00"
        + uint16(len(hostname))
        + hostname
    )

    server_name_list = uint16(len(server_name)) + server_name

    return encode_extension(0, server_name_list)


def build_signature_algorithms_extension():
    """Construct the signature algorithms extension."""

    algorithms = [
        0x0401,  # RSA PKCS1 SHA256
        0x0501,  # RSA PKCS1 SHA384
        0x0601,  # RSA PKCS1 SHA512
        0x0403,  # ECDSA SHA256
        0x0503   # ECDSA SHA384
    ]

    algorithm_bytes = b"".join(
        uint16(algorithm) for algorithm in algorithms
    )

    data = uint16(len(algorithm_bytes)) + algorithm_bytes

    return encode_extension(13, data)


def build_supported_groups_extension():
    """Construct the supported groups extension."""

    groups = [
        0x001D,  # X25519
        0x0017   # secp256r1
    ]

    group_bytes = b"".join(uint16(group) for group in groups)

    data = uint16(len(group_bytes)) + group_bytes

    return encode_extension(10, data)


def build_ec_point_formats_extension():
    """Construct the EC point formats extension."""

    formats = bytes([0])  # Uncompressed point format

    data = bytes([len(formats)]) + formats

    return encode_extension(11, data)


def build_alpn_extension():
    """Construct an ALPN extension offering HTTP/1.1."""

    protocol = b"http/1.1"

    protocol_list = bytes([len(protocol)]) + protocol

    data = uint16(len(protocol_list)) + protocol_list

    return encode_extension(16, data)


def build_client_hello(host):
    """Manually construct a TLS 1.2 ClientHello record."""

    # Selected cipher suites, in the order we want to advertise.
    cipher_suites = [
        0xC030,
        0xC02F,
        0xC02C,
        0xC02B,
        0x002F,
        0x0035
    ]

    cipher_bytes = b"".join(
        uint16(cipher) for cipher in cipher_suites
    )

    # Construct extensions in our chosen order.
    extensions = (
        build_sni_extension(host)
        + build_signature_algorithms_extension()
        + build_supported_groups_extension()
        + build_ec_point_formats_extension()
        + build_alpn_extension()
    )

    # TLS ClientHello body.
    body = (
        uint16(TLS_LEGACY_VERSION)
        + os.urandom(32)
        + b"\x00"  # Empty session ID
        + uint16(len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"  # Compression methods: null
        + uint16(len(extensions))
        + extensions
    )

    # TLS handshake header.
    handshake = (
        bytes([CLIENT_HELLO])
        + len(body).to_bytes(3, "big")
        + body
    )

    # TLS record header.
    record = (
        bytes([TLS_HANDSHAKE])
        + uint16(TLS_RECORD_VERSION)
        + uint16(len(handshake))
        + handshake
    )

    return record


def send_client_hello(host, port, timeout):
    """Send the custom ClientHello to a TLS server."""

    client_hello = build_client_hello(host)

    print(f"Destination: {host}:{port}")
    print("TLS version advertised: TLS 1.2")
    print(f"ClientHello size: {len(client_hello)} bytes")

    with socket.create_connection(
        (host, port),
        timeout=timeout
    ) as connection:

        connection.settimeout(timeout)

        print(f"Connected to: {connection.getpeername()}")

        connection.sendall(client_hello)

        print("Custom ClientHello sent successfully.")

        try:
            response = connection.recv(4096)

            if response:
                print(
                    f"Received {len(response)} bytes "
                    "in the server's initial response."
                )
            else:
                print("Server closed the connection.")

        except socket.timeout:
            print("No server response received before timeout.")

    print("Connection closed.")
    print("A complete TLS handshake was not attempted.")


def main():

    parser = argparse.ArgumentParser(
        description="Send a manually constructed TLS ClientHello."
    )

    parser.add_argument(
        "host",
        help="Destination hostname, such as example.com"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Destination port (default: 443)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3,
        help="Socket timeout in seconds (default: 3)"
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")

    if args.timeout <= 0:
        parser.error("Timeout must be positive.")

    try:
        send_client_hello(
            args.host,
            args.port,
            args.timeout
        )

    except OSError as error:
        parser.error(f"Network error: {error}")


if __name__ == "__main__":
    main()
