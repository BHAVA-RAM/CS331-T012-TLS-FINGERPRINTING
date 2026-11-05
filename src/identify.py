
import argparse
import hashlib
import json
from pathlib import Path

from scapy.all import IP, IPv6, load_layer, sniff
from scapy.layers.tls.handshake import TLSClientHello
from scapy.sessions import TCPSession

from ja3 import calculate_ja3
from ja4 import calculate_ja4


DATABASE_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "fingerprints.json"
)

DATABASE_SCHEMA_VERSION = 3
SUPPORTED_METHODS = {"JA3", "JA4"}


def get_endpoints(packet):
    """Return source and destination IP addresses from an IP packet."""
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return "Unknown", "Unknown"


def load_database(database_path):
    """Load and validate the schema-v3 client fingerprint catalogue."""
    with database_path.open("r", encoding="utf-8") as file:
        database = json.load(file)

    if not isinstance(database, dict):
        raise ValueError("Fingerprint database must be a JSON object.")

    if database.get("schema_version") != DATABASE_SCHEMA_VERSION:
        raise ValueError(
            f"Expected fingerprint database schema version "
            f"{DATABASE_SCHEMA_VERSION}."
        )

    records = database.get("fingerprints")
    if not isinstance(records, list):
        raise ValueError("Database must contain a 'fingerprints' list.")

    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Fingerprint record #{index} must be an object.")

        if record.get("endpoint") != "client":
            raise ValueError(
                f"Record #{index} has an unsupported endpoint; expected 'client'."
            )

        mechanism = record.get("mechanism")
        if mechanism not in SUPPORTED_METHODS:
            raise ValueError(
                f"Record #{index} uses unsupported mechanism {mechanism!r}."
            )

        fingerprint_string = record.get("fingerprint_string")
        if not isinstance(fingerprint_string, str) or not fingerprint_string:
            raise ValueError(
                f"Record #{index} must contain a non-empty fingerprint_string."
            )

        identifier = record.get("identifier")
        if not isinstance(identifier, dict):
            raise ValueError(f"Record #{index} must contain an identifier object.")

        identifier_type = identifier.get("type")
        identifier_value = identifier.get("value")

        if mechanism == "JA3":
            if identifier_type != "md5":
                raise ValueError(
                    f"JA3 record #{index} must use an MD5 identifier."
                )

            if not isinstance(identifier_value, str) or len(identifier_value) != 32:
                raise ValueError(f"JA3 record #{index} has an invalid MD5 value.")

            calculated_hash = hashlib.md5(
                fingerprint_string.encode("utf-8")
            ).hexdigest()

            if calculated_hash != identifier_value.lower():
                raise ValueError(
                    f"JA3 hash/string mismatch in fingerprint record #{index}."
                )

        elif mechanism == "JA4":
            if identifier_type != "exact":
                raise ValueError(
                    f"JA4 record #{index} must use an exact-string identifier."
                )

            if identifier_value != fingerprint_string:
                raise ValueError(
                    f"JA4 identifier/string mismatch in fingerprint record #{index}."
                )

        observations = record.get("observations")
        if not isinstance(observations, list) or not observations:
            raise ValueError(
                f"Record #{index} must contain at least one observation."
            )

        for observation in observations:
            if not isinstance(observation, dict) or not observation.get("client_name"):
                raise ValueError(
                    f"Record #{index} contains an observation without client_name."
                )

    return records


def find_matches(mechanism, fingerprint_string, identifier_value, records):
    """Find all client records matching the selected fingerprint mechanism."""
    identifier_type = "md5" if mechanism == "JA3" else "exact"
    matches = []

    for record in records:
        if record.get("endpoint") != "client":
            continue

        if record.get("mechanism") != mechanism:
            continue

        stored_identifier = record["identifier"]

        if stored_identifier.get("type") != identifier_type:
            continue

        if stored_identifier.get("value", "").lower() != identifier_value.lower():
            continue

        if record.get("fingerprint_string") != fingerprint_string:
            continue

        matches.append(record)

    return matches


def display_matches(matches):
    """Display every software candidate associated with matching records."""
    if not matches:
        print("  Result: Unknown client (fingerprint not found in database)")
        return 0

    candidate_count = 0

    for record_index, record in enumerate(matches, start=1):
        print(
            f"  Matching fingerprint entry #{record_index}: "
            f"{record['mechanism']} / {record['identifier']['value']}"
        )

        for observation in record["observations"]:
            candidate_count += 1
            print(f"\n    Candidate #{candidate_count}")
            print(f"      Software:            {observation['client_name']}")

            version = observation.get("client_version")
            if version:
                print(f"      Software version:    {version}")

            library = observation.get("tls_library")
            if library:
                print(f"      TLS library:         {library}")

            library_version = observation.get("tls_library_version")
            if library_version:
                print(f"      TLS library version: {library_version}")

            runtime = observation.get("runtime")
            if runtime:
                print(f"      Runtime:             {runtime}")

            evidence = observation.get("sample_count")
            if evidence is not None:
                print(f"      Reference samples:  {evidence}")

            captures = observation.get("capture_files", [])
            if captures:
                print(f"      Evidence captures:  {', '.join(captures)}")

            notes = observation.get("notes")
            if notes:
                print(f"      Notes:               {notes}")

    return candidate_count


def identify_clients(capture_file, records):
    """Extract ClientHello messages and identify both JA3 and JA4."""
    load_layer("tls")

    packets = sniff(
        offline=str(capture_file),
        session=TCPSession,
        store=True
    )

    print(f"Capture file: {capture_file}")
    print(f"Total packets: {len(packets)}")

    client_hello_count = 0
    method_stats = {
        "JA3": {"matched": 0, "unknown": 0, "candidates": 0},
        "JA4": {"matched": 0, "unknown": 0, "candidates": 0}
    }

    for packet in packets:
        if TLSClientHello not in packet:
            continue

        client_hello_count += 1
        hello = packet[TLSClientHello]
        source, destination = get_endpoints(packet)

        print(f"\nClientHello #{client_hello_count}")
        print(f"  Source:      {source}")
        print(f"  Destination: {destination}")

        # Calculate JA3. Its matching identifier is the MD5 of the JA3 string.
        try:
            ja3_string, ja3_hash = calculate_ja3(hello)
            print(f"\n  JA3 string:  {ja3_string}")
            print(f"  JA3 MD5:     {ja3_hash}")

            ja3_matches = find_matches(
                "JA3", ja3_string, ja3_hash, records
            )
            if ja3_matches:
                method_stats["JA3"]["matched"] += 1
            else:
                method_stats["JA3"]["unknown"] += 1

            method_stats["JA3"]["candidates"] += display_matches(ja3_matches)

        except (TypeError, ValueError, AttributeError) as error:
            print(f"\n  JA3 calculation failed: {error}")

        # Calculate JA4. The complete canonical JA4 string is its identifier.
        try:
            ja4_fingerprint = calculate_ja4(hello)
            print(f"\n  JA4:         {ja4_fingerprint}")

            ja4_matches = find_matches(
                "JA4", ja4_fingerprint, ja4_fingerprint, records
            )
            if ja4_matches:
                method_stats["JA4"]["matched"] += 1
            else:
                method_stats["JA4"]["unknown"] += 1

            method_stats["JA4"]["candidates"] += display_matches(ja4_matches)

        except (TypeError, ValueError, AttributeError) as error:
            print(f"\n  JA4 calculation failed: {error}")

    print("\n--- Summary ---")
    print(f"ClientHello messages processed: {client_hello_count}")

    for mechanism in ("JA3", "JA4"):
        stats = method_stats[mechanism]
        print(f"\n{mechanism}:")
        print(f"  Known fingerprints:   {stats['matched']}")
        print(f"  Unknown fingerprints: {stats['unknown']}")
        print(f"  Software candidates:  {stats['candidates']}")

    if client_hello_count == 0:
        print("No TLS ClientHello messages were found in this capture.")


def main():
    parser = argparse.ArgumentParser(
        description="Identify TLS clients using JA3 and JA4 fingerprints."
    )

    parser.add_argument(
        "pcap",
        type=Path,
        help="Path to the input PCAP or PCAPNG file"
    )

    parser.add_argument(
        "--database",
        type=Path,
        default=DATABASE_FILE,
        help="Path to the schema-v3 fingerprint JSON database"
    )

    args = parser.parse_args()

    if not args.pcap.is_file():
        parser.error(f"Capture file not found: {args.pcap}")

    if not args.database.is_file():
        parser.error(f"Fingerprint database not found: {args.database}")

    try:
        records = load_database(args.database)
        identify_clients(args.pcap, records)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
