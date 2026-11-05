# Setup Guide

This guide describes the development environment used for the project and a reproducible local setup. Run commands from the repository root unless stated otherwise.

## 1. Prerequisites

- Linux environment; the development work was performed in Ubuntu under WSL2.
- Python 3.12.x (the recorded development environment used Python 3.12.3).
- Git.
- `tcpdump` for packet capture and/or Wireshark for graphical capture and inspection.
- Docker is optional and was used for the curl-impersonation experiment.

The machine-specific CPU, memory, Windows build, and exact Ubuntu release should be recorded by the team before final submission. They are intentionally not guessed here.

## 2. Install system tools

On Ubuntu/WSL:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump
```

Wireshark is optional if packet capture or inspection is performed with its GUI. Docker Desktop with WSL integration is optional unless reproducing the impersonation experiment.

## 3. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python --version
```

The development environment used Python 3.12.3. Use the version recorded by the project team if it differs on another machine.

## 4. Install Python dependencies

The packet parsing implementation uses Scapy. Install it with:

```bash
python -m pip install --upgrade pip
python -m pip install scapy
```

If the repository includes a maintained `requirements.txt`, prefer installing the pinned project dependencies with:

```bash
python -m pip install -r requirements.txt
```

Keep `requirements.txt` synchronized with the imports actually used by the checked-in source. Do not generate it from the entire virtual environment without reviewing it.

## 5. Verify the project layout

The scripts expect to be run from the repository root. The relevant paths are:

```text
src/identify.py
src/ja3.py
src/ja3s.py
src/ja4.py
data/fingerprints.json
captures/
experiments/
test/run_wire_demo.py
```

Check that the reference database and capture files have been committed. Large or sensitive PCAPs may need to be excluded or stored separately; see [Limitations and security notes](limitations.md).

## 6. Optional: packet capture with tcpdump

For a short test capture, choose the correct interface for the environment:

```bash
sudo tcpdump -i any -s 0 -U -w experiments/sample.pcap 'tcp port 443'
```

Generate a TLS connection from another terminal, then stop `tcpdump` with `Ctrl+C`. The `any` interface is convenient in Linux/WSL, but Docker Desktop networking can require capturing in the container network namespace instead. Verify that the capture file is non-empty before analysis.

## 7. Optional: Docker-based curl impersonation experiment

The experiment used the `lexiforest/curl-impersonate` Docker image and its `curl_chrome152` command. Reproduction instructions are in [Experiments and results](experiments-and-results.md). This is an optional experiment, not a runtime dependency of the fingerprinting application.
