# TLSBreaker — AI-Powered SSL/TLS Security Testing Suite

> **For educational and authorized penetration testing purposes only.**  
> Unauthorized use against systems you do not own or have explicit permission to test is illegal.

TLSBreaker is a web-based SSL/TLS vulnerability research platform that combines classical attack tooling with a machine-learning classifier to assess the security posture of TLS configurations. It wraps five specialized attack/analysis modules behind a real-time Flask + Socket.IO dashboard, containerized with Docker for reproducible deployment.

---

## Features

- **SSL Stripping Attack** — Intercepts and downgrades HTTPS connections to HTTP (requires ARP spoofing + iptables setup).
- **SSL/TLS Version Rollback** — Forces negotiation of weak protocol versions (SSLv2/3, TLS 1.0/1.1) via automated MITM proxy.
- **Cipher Downgrade Attack** — Coerces weak cipher suites (RC4, DES, 3DES) during the TLS handshake.
- **Heartbleed Exploit** — Probes and exploits CVE-2014-0160 to extract heap memory from vulnerable OpenSSL instances.
- **AI SSL Orchestrator** — Feeds `sslscan` output into a trained Random Forest model, automatically selects the most relevant attack vector, and executes it.
- **ML Domain Security Tester** — Scores any domain against 14 TLS security features using the pre-trained `ssl_security_model.pkl` classifier.
- **HTML Audit Report Generator** — Produces a structured report with per-tool results, severity classification, and prioritized remediation recommendations.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Web framework | Flask 3.0 + Flask-SocketIO 5.3 |
| Real-time I/O | Socket.IO (eventlet) |
| ML model | scikit-learn (Random Forest) |
| Packet crafting | Scapy |
| TLS scanning | sslscan, pyOpenSSL |
| Data processing | pandas, numpy |
| Legacy TLS support | OpenSSL 1.0.2u (compiled from source) |
| Containerization | Docker (python:3.12-slim-bookworm) |

---

## Project Structure

```
phase5/
├── app.py                        # Flask app — routes, Socket.IO, report generator
├── train_model.py                # Trains the Random Forest SSL security classifier
├── ssl_security_model.pkl        # Pre-trained ML model
├── model_features.pkl            # Feature list used for inference
├── datav2.csv                    # Labeled SSL/TLS configuration dataset
├── Dockerfile                    # Container build (includes legacy OpenSSL 1.0.2u)
├── templates/
│   └── index.html                # Frontend dashboard
├── phase4-tools/
│   ├── ssl_strip.py              # SSL stripping module
│   ├── ssl_downgrade.py          # Protocol rollback module
│   ├── cipher_downgrade.py       # Cipher downgrade module
│   ├── heartbleed_exploit.py     # Heartbleed CVE-2014-0160 module
│   ├── ai_ssl_orchestrator.py    # AI-driven attack orchestrator
│   └── test_domain.py            # ML-based domain security tester
└── logs/                         # Per-run attack/scan logs
```

---

## Getting Started

### Prerequisites

- Docker
- A Linux host with network interface access (required for MITM modules)
- Root/sudo privileges for ARP spoofing and iptables rules

### Build & Run

```bash
git clone https://github.com/<your-username>/tlsbreaker.git
cd tlsbreaker
docker build -t tlsbreaker .
docker run --rm -it --privileged --network host -p 5000:5000 tlsbreaker
```

> `--privileged` and `--network host` are required for modules that use raw sockets and ARP spoofing.

Open your browser at `http://localhost:5000`.

### (Re)train the ML Model

If you want to retrain on updated data:

```bash
python3 train_model.py
```

This reads `datav2.csv`, trains a 100-estimator Random Forest on 14 TLS security features, prints accuracy + feature importance, and writes `ssl_security_model.pkl` and `model_features.pkl`.

---

## ML Model Details

The classifier predicts whether a TLS configuration is **secure** (`is_secure`) based on the following features:

| Feature | Description |
|---|---|
| `sslv2_supported` | Legacy SSLv2 enabled |
| `sslv3_supported` | Legacy SSLv3 enabled |
| `tlsv1_0_supported` | TLS 1.0 enabled |
| `tlsv1_1_supported` | TLS 1.1 enabled |
| `tlsv1_2_supported` | TLS 1.2 supported |
| `tlsv1_3_supported` | TLS 1.3 supported |
| `heartbleed_vulnerable` | Vulnerable to CVE-2014-0160 |
| `poodle_vulnerable` | Vulnerable to POODLE |
| `secure_renegotiation` | RFC 5746 renegotiation supported |
| `weak_ciphers` | Any weak cipher offered |
| `rc4_ciphers` | RC4 cipher offered |
| `des_ciphers` | DES/3DES cipher offered |
| `cert_expiry_days` | Days until certificate expiry |
| `cert_bits` | Certificate key length (bits) |

---

## Modules

### AI SSL Orchestrator

Runs `sslscan`, extracts the 14 features above, feeds them to the ML model, then maps detected weaknesses to the most appropriate attack module and executes it automatically.

```bash
python3 phase4-tools/ai_ssl_orchestrator.py --target example.com --port 443 [--auto-mode] [--test-mode]
```

### Test Domain Security

Standalone ML-based assessment without launching an attack:

```bash
python3 phase4-tools/test_domain.py --target example.com
```

### Individual Attack Modules

Each module supports a `--test-mode` flag for detection-only runs (no active exploitation):

```bash
python3 phase4-tools/ssl_downgrade.py --target example.com --victim-ip 192.168.1.10
python3 phase4-tools/cipher_downgrade.py --target example.com --victim-ip 192.168.1.10
python3 phase4-tools/ssl_strip.py --target example.com --victim-ip 192.168.1.10
python3 phase4-tools/heartbleed_exploit.py --target example.com --port 443 --verbose
```

---

## Report Generation

After running tools via the dashboard, click **Generate Report** to produce an HTML audit report saved to `/opt/ssl-tls-suite/reports/`. Reports include:

- Executive summary (total tests, vulnerabilities found, critical issues, warnings)
- Per-tool output with severity color-coding (critical / warning / success / error)
- Prioritized remediation recommendations (HSTS enforcement, protocol hardening, cipher restrictions, certificate renewal)

---

## Disclaimer

This tool is intended exclusively for:

- Academic research and coursework
- Authorized penetration testing engagements
- Security awareness and lab environments

Do **not** run attack modules against systems without explicit written authorization. The authors assume no liability for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
