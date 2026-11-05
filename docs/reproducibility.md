# Reproducibility Guide

## 1. Obtain the source

Clone the project repository after it has been created on GitHub:

```bash
git clone https://github.com/<GITHUB-USERNAME>/<REPOSITORY-NAME>.git
cd <REPOSITORY-NAME>
```

Replace the placeholders with the team's actual repository URL.

## 2. Prepare the environment

Follow [Setup Guide](setup.md) to create and activate `.venv` and install the project's Python dependencies.

## 3. Run identification on one capture

From the repository root:

```bash
python src/identify.py experiments/repeat_curl.pcap
```

Replace the path with another PCAP or PCAPNG file to analyze a different capture. The script prints the ClientHello message details, JA3 and JA4 values, reference matches, and summary counts.

## 4. Run the selected experiment suite

```bash
python test/run_wire_demo.py
```

The runner expects the capture paths defined in its `TESTS` list to exist under `experiments/`. If a capture is intentionally not distributed, remove its entry from the runner or document how to reproduce it before running the suite.

The runner's execution summary reports whether each analyzer subprocess completed. Inspect the individual JA3 and JA4 summaries to determine fingerprint recognition results.

## 5. Reproduce the Chrome-like curl impersonation test (optional)

This experiment requires Docker. The recorded workflow used a separate container network namespace so that packets generated inside the curl-impersonate container could be captured.

Start the client container:

```bash
docker pull lexiforest/curl-impersonate:latest

docker run -d \
  --name curl-chrome-capture \
  --entrypoint sleep \
  lexiforest/curl-impersonate:latest 600
```

From the project root, start a capture container in the same network namespace:

```bash
docker run --rm \
  --network container:curl-chrome-capture \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v "$PWD/experiments:/captures" \
  nicolaka/netshoot \
  tcpdump -i any -nn -s 0 -U \
  -w /captures/curl_chrome152.pcap 'tcp port 443'
```

While capture is running, use another terminal to generate the traffic:

```bash
docker exec curl-chrome-capture \
  curl_chrome152 -I https://example.com
```

Stop the capture with `Ctrl+C`, then remove the client container:

```bash
docker rm -f curl-chrome-capture
```

Analyze the resulting capture:

```bash
python src/identify.py experiments/curl_chrome152.pcap
```

The observed result in the team's experiment was an unknown JA3 and a JA4 match to a Chrome reference entry. The match is an example of profile impersonation, not proof of the real application identity. Container image tags and remote image contents may change over time; preserve the tested image details if exact long-term reproducibility is required.

## 6. Reproduce packet capture with tcpdump (optional)

For ordinary TLS-over-TCP traffic, capture with:

```bash
sudo tcpdump -i any -s 0 -U -w experiments/new_capture.pcap 'tcp port 443'
```

Generate a connection from a separate terminal and stop the capture with `Ctrl+C`. If traffic originates inside Docker, confirm that the chosen interface sees the container traffic; otherwise capture within the container network namespace as shown above.

## 7. Expected outputs

The exact packet count and source/destination addresses depend on the environment. The stable expected behavior is:

- A readable capture is opened by `identify.py`.
- Every successfully extracted ClientHello produces JA3 and JA4 values.
- Database matches are shown as candidates associated with the matching reference entry.
- Non-matching fingerprints are shown as unknown.
- The program prints the number of ClientHello messages and known/unknown summary counts.

Do not treat an unknown result as a program failure. Do not treat successful script execution as proof that every fingerprint was recognized.

## 8. Environment details to record for a final reproducibility submission

Record the exact values from the machine used for the final evaluation:

```bash
python --version
uname -a
tcpdump --version
docker --version
```

Also record the capture interface, capture date, software versions of each client under test, and the exact reference database revision used for the result.
