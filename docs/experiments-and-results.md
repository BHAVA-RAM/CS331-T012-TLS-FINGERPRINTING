# Experiments and Results

## 1. Experimental method

Reference captures were first collected for known client/tool profiles and used to populate `data/fingerprints.json`. Separate PCAP files were then captured for repeatability tests. The experiment captures were passed to `src/identify.py`; they were not automatically promoted into the reference database.

The current selected reference profiles are curl, Google Chrome, GnuTLS CLI, Go `crypto/tls`, and Python standard-library `ssl`. A custom OpenSSL TLS client capture was used as an unknown-profile test.

## 2. Repeat-capture evaluation

The following table summarizes the supplied demonstration output. `Known` and `Unknown` counts refer to the number of ClientHello messages in that capture for which a database match was or was not found.

| Experimental capture | ClientHello messages | JA3 known | JA3 unknown | JA4 known | JA4 unknown |
|---|---:|---:|---:|---:|---:|
| `repeat_curl.pcap` | 5 | 5 | 0 | 5 | 0 |
| `repeat_chrome.pcapng` | 2 | 1 | 1 | 2 | 0 |
| `repeat_gnutls.pcap` | 5 | 0 | 5 | 5 | 0 |
| `repeat_go.pcap` | 5 | 5 | 0 | 5 | 0 |
| `repeat_python_ssl.pcap` | 5 | 5 | 0 | 5 | 0 |

The custom OpenSSL experiment (`capture_10_openssl_custom_tls.pcap`) contained one ClientHello. Its JA3 and JA4 values were both unknown to the current reference database. This is an expected unknown-profile outcome, not an execution failure.

## 3. Observations

### 3.1 curl

All five ClientHello messages in `repeat_curl.pcap` matched a curl reference entry for both JA3 and JA4. This demonstrates repeatability for the tested curl version and configuration.

### 3.2 Chrome

The filtered Chrome capture contained two ClientHello messages. JA3 recognized one and did not recognize the other. JA4 matched both against Chrome reference entries. This is evidence that, for these observed messages, JA4 was less sensitive to the variation present in this capture. It is not a claim that all Chrome versions or configurations will always produce one stable JA4 value.

### 3.3 GnuTLS

The five messages in `repeat_gnutls.pcap` produced five JA3 values not present in the reference database, while all five JA4 values matched the same GnuTLS reference profile. The supplied capture shows extension-order variation affecting JA3 while the normalized JA4 result remained consistent.

### 3.4 Go crypto/tls

All five messages matched the Go reference profile using both JA3 and JA4.

### 3.5 Python standard-library ssl

All five messages matched the Python standard-library SSL reference profile using both JA3 and JA4.

### 3.6 Custom OpenSSL TLS client

The custom OpenSSL capture produced unknown JA3 and JA4 values. This demonstrates the unknown-profile path: the tool does not invent an identity when the reference database has no match.

## 4. Impersonation experiment: curl-impersonate using a Chrome profile

A separate experiment used the `curl-impersonate` Docker image with the `curl_chrome152` profile to generate a Chrome-like ClientHello. The traffic was captured from the container's network namespace and analyzed using the same `identify.py` program.

Observed output:

| Field | Result |
|---|---|
| Actual program used | `curl-impersonate` |
| Selected profile | Chrome 152 impersonation profile |
| JA3 | `32bf25b02f50b9110ced3f768df1cd4e` — unknown |
| JA4 | `t13d1517h2_8daaf6152771_cb7bf5808d99` — matched a Chrome reference entry |

The reference record associated with that JA4 value describes Google Chrome 156.0.8078.80. The experiment's actual configured impersonation profile was Chrome 152. Therefore the output demonstrates a Chrome-like profile match, not proof that Chrome 156 was running. The experiment shows how a program can imitate handshake characteristics and be attributed to a misleading reference candidate.

## 5. Interpretation

For the tested captures, JA4 recognized the Chrome and GnuTLS variants that were not recognized by JA3. JA3 and JA4 both identified the tested curl, Go, and Python standard-library SSL messages. These findings are limited to the captured software versions, configurations, and destinations. They should not be generalized into universal accuracy rates.

The five supported reference profiles satisfy the project's demonstration goal of matching at least five client/tool profiles. The separate custom OpenSSL and curl-impersonation experiments demonstrate unknown and misleading-match cases, respectively.
