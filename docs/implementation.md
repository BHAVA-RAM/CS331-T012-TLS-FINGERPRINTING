# Implementation Details

## 1. Language and libraries

- **Language:** Python.
- **Packet analysis:** Scapy.
- **TCP/TLS capture input:** PCAP and PCAPNG files produced by `tcpdump` or Wireshark.
- **Reference data:** JSON (`data/fingerprints.json`).
- **Execution:** Python scripts run from the project root in a virtual environment.

## 2. JA3 client fingerprint

JA3 summarizes selected ClientHello fields in this order:

```text
TLSVersion,CipherSuites,Extensions,SupportedGroups,ECPointFormats
```

Values within a field are represented as decimal identifiers separated by hyphens; the fields are separated by commas. The resulting canonical string is hashed with MD5 to produce the familiar 32-character JA3 value. GREASE values are excluded so that GREASE codepoints do not create needless fingerprint changes.

The project calculates the canonical value from the parsed ClientHello rather than relying on an application-level user-agent string. The result is therefore based on handshake characteristics visible in the capture.

## 3. JA3S server fingerprint

JA3S applies the analogous idea to the ServerHello. It uses the negotiated TLS version, selected cipher suite, and ServerHello extension identifiers. The JA3S string is hashed to produce the server fingerprint.

JA3S complements JA3: the client fingerprint describes the ClientHello profile, while JA3S describes the server's response profile. A server response can depend on the client's offer and the server's configuration, so JA3S should be interpreted in the context of the observed connection.

## 4. JA4 client fingerprint

JA4 creates a structured fingerprint from ClientHello characteristics. Its leading portion summarizes transport/TLS version, SNI presence, cipher and extension counts, and ALPN information. The remaining sections contain truncated SHA-256 digests derived from normalized cipher and extension/signature-algorithm information. GREASE values are ignored.

A key difference from JA3 is that JA4 sorts selected lists before hashing. This reduces sensitivity to some ordering changes, such as extension-order variation. It does not make a fingerprint permanent or prove an application identity: software versions and TLS configurations can still change the result, and another client can deliberately imitate a profile.

## 5. Identification database

`data/fingerprints.json` contains reference entries for the supported client profiles. Records contain fingerprint values and descriptive metadata such as software name, version, TLS library, and evidence capture. The database is a set of reference profiles, not a repository of every experimental observation.

`identify.py` calculates the fingerprint(s) from each ClientHello and looks for matching entries. For each message it displays:

- source and destination address;
- JA3 string and hash;
- JA4 value;
- matching reference record(s), where available;
- an unknown result when no record matches.

The output can contain multiple candidates when a fingerprint is shared. The program therefore reports database matches; it does not independently verify which executable created the traffic.

## 6. Batch demonstration

`test/run_wire_demo.py` runs the identification script against the project's selected experiment captures. It uses the Python interpreter running the demo, executes the analyzer as a subprocess, labels each capture, and prints a summary of script execution failures.

The runner's `Completed` count means that the analyzer process returned successfully. Fingerprint match rates must be read from the individual JA3 and JA4 summaries, not inferred from the runner's completion count.

## 7. Error handling and implementation considerations

- The analyzer checks whether the capture and reference database can be read.
- The database matcher checks that stored JA3 values are internally consistent with their JA3 strings.
- TCP reassembly is needed when handshake messages are segmented across packets.
- Captures with no ClientHello messages cannot produce client-identification results.
- Unknown fingerprints are retained as unknown rather than being forced into the nearest database profile.

## 8. Current boundaries

JA4S is not implemented. The project does not decrypt TLS application data, attribute a flow to a local process, or perform automated production alerting. These would be separate extensions.
