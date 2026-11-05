# Project Overview

## 1. Purpose

This project implements a passive TLS fingerprinting tool. It reads captured TLS traffic, extracts the ClientHello and ServerHello handshake messages, calculates fingerprints, and compares client fingerprints with a small local reference database.

The central idea is that TLS handshakes expose implementation and configuration characteristics before application data is encrypted. These characteristics can be summarized into fingerprints and used to group traffic that appears to originate from a known TLS client implementation.

## 2. Objectives

- Read packet captures containing TLS over TCP traffic.
- Extract TLS ClientHello messages and calculate JA3 and JA4 client fingerprints.
- Extract TLS ServerHello messages and calculate JA3S server fingerprints.
- Compare calculated client fingerprints with entries in `data/fingerprints.json`.
- Report known matches, candidate software profiles, and unknown fingerprints.
- Demonstrate identification using captures from at least five distinct client/tool profiles.
- Evaluate fingerprint variation and show why a fingerprint match is not proof of application identity.

## 3. Implemented scope

| Capability | Current status |
|---|---|
| PCAP/PCAPNG analysis | Implemented |
| ClientHello parsing | Implemented |
| JA3 | Implemented |
| JA3S | Implemented |
| JA4 | Implemented |
| Reference database matching | Implemented |
| Batch demonstration runner | Implemented in `test/run_wire_demo.py` |
| JA4S | Not implemented |
| Live inline monitoring / alerting | Not implemented |
| eBPF/XDP acceleration | Not implemented |
| TRex traffic generation | Not implemented |
| Redis/Valkey storage | Not implemented |

## 4. Client/tool profiles used in the reference set

The curated reference set is intended to identify these five profiles:

1. curl
2. Google Chrome
3. GnuTLS CLI
4. Go `crypto/tls`
5. Python standard-library `ssl`

A separate custom OpenSSL TLS client capture is retained as an experimental unknown case. It is not treated as an additional known reference profile.

## 5. Intended use

The tool is a learning and prototype security-monitoring aid. Fingerprints can help group similar TLS handshakes, identify unexpected client profiles, and support traffic investigations. They should be used as supporting evidence alongside other network and endpoint signals, not as definitive application authentication.

## 6. Out of scope

The current project does not decrypt application payloads, authenticate the endpoint process, identify a user, or guarantee unique application attribution. It does not implement a production-scale streaming collector, centralized database, dashboard, automated alerting, or high-performance kernel packet processing.
