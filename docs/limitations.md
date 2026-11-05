# Limitations and Security Notes

## 1. Fingerprint matches are not authenticated identities

JA3, JA3S, and JA4 summarize observable handshake properties. They do not cryptographically prove which application, process, or TLS library created a connection. A client can configure or modify its handshake to resemble another implementation. The curl-impersonate experiment demonstrated this: the actual program was curl-impersonate, but its JA4 matched a Chrome reference profile.

For this reason, output should be described as a **matching fingerprint profile** or **candidate application**, not verified application identity.

## 2. Deliberate spoofing and impersonation

A malicious or customized client can imitate the cipher suites, extensions, supported groups, ALPN information, and other observable characteristics of a known client. If those fields produce a stored fingerprint, a passive system may report the corresponding known profile. A defender should correlate fingerprint results with process telemetry, endpoint inventory, destination reputation, certificate and protocol context, and other signals where available.

## 3. Shared fingerprints and ambiguous candidates

Different applications or configurations can produce identical JA3 or JA4 values. When multiple reference records share a fingerprint, the system can only return the associated candidate set. A single match does not mean that the fingerprint is unique to that product.

## 4. Fingerprint variation over time

TLS library upgrades, application versions, configuration changes, platform differences, and browser behavior can change ClientHello fields. Traditional JA3 is sensitive to the order of the fields it incorporates. JA4 sorts selected cipher and extension lists, which can reduce sensitivity to ordering changes, but JA4 values can still change as implementations evolve.

## 5. Reference database coverage

The system can identify only profiles represented in its database. New clients, custom TLS configurations, and modified implementations may be reported as unknown. The database also requires versioned maintenance as applications and TLS libraries change.

## 6. Capture and parsing limitations

- Packet loss, truncated captures, incorrect capture interfaces, or incomplete TCP streams can prevent reliable handshake extraction.
- TLS 1.3 encrypts handshake messages after ServerHello; the project focuses on the unencrypted hello messages used by its current extractors.
- The current tool analyzes saved captures rather than operating as a continuous production sensor.
- The implementation does not decrypt application data or map packets to the local originating process.

## 7. Operational and privacy considerations

PCAP files can contain IP addresses, DNS names, timing information, and other metadata. Before publishing captures, inspect them for sensitive internal addresses, usernames, tokens, session material, or unrelated traffic. Do not commit private keys, TLS key logs, `.env` files, credentials, or personal traffic captures. Include only captures that the team is authorized to share.

## 8. Future work

Potential extensions include JA4S, larger versioned reference datasets, automated capture and streaming analysis, flow correlation, endpoint telemetry integration, alerting, a web dashboard, and performance testing with traffic generators or kernel-level capture. eBPF/XDP, TRex, Redis, and Valkey are possible future technologies, not current project components.
