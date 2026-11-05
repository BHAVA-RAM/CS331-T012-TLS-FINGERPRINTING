# Project Documentation

This directory contains the technical documentation for the passive TLS fingerprinting project. The repository root `README.md` is intentionally reserved for team-member names, as required by the project instructions.

| Document | Contents |
|---|---|
| [Project overview](project-overview.md) | Scope, goals, supported fingerprints, and project boundaries |
| [Setup guide](setup.md) | Local environment, dependencies, and tools |
| [Architecture](architecture.md) | Packet-to-fingerprint processing pipeline and component responsibilities |
| [Implementation](implementation.md) | JA3, JA3S, JA4, database matching, and program interfaces |
| [Experiments and results](experiments-and-results.md) | Captures, measured matches, repeatability, and impersonation experiment |
| [Limitations and security notes](limitations.md) | Spoofing, fingerprint collisions, coverage, and privacy considerations |
| [Reproducibility guide](reproducibility.md) | Commands to run the identification and demonstration scripts |
| [AI usage record](ai-usage.md) | Checklist for documenting AI assistance and prompt logs |
| [References](references.md) | Specifications and implementation references |

> **Accuracy note:** The documentation describes the current PCAP-based implementation. Packet capture is performed using external tools (such as `tcpdump` or Wireshark); the Python program analyzes the resulting capture. JA4S, eBPF/XDP, TRex, Redis, and Valkey are not claimed as implemented components.
