# NetWatch AI — Network Intelligence Assistant

[![CI](https://github.com/growlf/netyeti-netwatcher/actions/workflows/ci.yml/badge.svg)](https://github.com/growlf/netyeti-netwatcher/actions/workflows/ci.yml)
[![Docker Build](https://github.com/growlf/netyeti-netwatcher/actions/workflows/docker-build.yml/badge.svg)](https://github.com/growlf/netyeti-netwatcher/actions/workflows/docker-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/github/v/release/growlf/netyeti-netwatcher?label=version)](https://github.com/growlf/netyeti-netwatcher/releases)

**NetWatch AI** is a local LLM-powered network awareness, anomaly detection, and diagnostic assistant. It maintains a complete, queryable graph of your network, detects proactive anomalies, and provides natural language interactions — without relying on external cloud services.

## Overview

> [!WARNING]
> **Project Status: Prototype / Rapid Development**
> NetWatch AI is currently in active prototype development. Features, data structures, and the user interface are changing rapidly.

### Current Hardware Support

NetWatch AI currently supports direct API/SSH polling for:
- **MikroTik RouterOS** (v6 and v7 via SSH/API)
- **Proxmox VE** (via Proxmoxer API)
- **Technitium DNS**

### Planned Features

- **Local and Remote LLM Support**: Query your network topology using natural language (LlamaIndex).
- **Interactive Network Mapping**: Visual graphs to explore nodes and links.
- **Alerting & Charting**: Grafana integrations and alerting for anomalies.
- **Enhanced Telemetry**: Expanding support to Ubiquiti, Cisco, and more.

> [!TIP]
> **Have a device you want supported?**
> Please [open a Feature Request](https://github.com/growlf/netyeti-netwatcher/issues/new?template=feature_request.md) on GitHub! We prioritise hardware based on community requests.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Collection Layer                       │
│  nmap/SNMP  │  Node Exporters  │  SSH/API Pollers        │
│  (Discovery)│  (Metrics)       │  (MikroTik, Proxmox…)  │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                    Storage Layer                         │
│  Kuzu (Graph DB)  │  VictoriaMetrics  │  Chroma (Vector) │
│  Devices/Topology │  Metrics/Health   │  Semantic Index  │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│              Retrieval & Reasoning Layer                 │
│      LlamaIndex RAG  →  Ollama LLM (local)              │
│      "Which hosts changed on VLAN 10 today?"            │
└─────────────────────────────────────────────────────────┘
```

The system is built on a 100% local, self-hosted stack:
- **Kuzu** — Embeddable graph database for devices, interfaces, and topology.
- **VictoriaMetrics** — Time-series database for latency, bandwidth, and health metrics.
- **Chroma** — Vector database for semantic summaries and anomaly events.
- **Telemetry Agents** — Python agents running nmap discovery and direct device API/SSH polling.

For the full architecture and roadmap see:
👉 **[docs/netwatch_ai_project_plan.md](docs/netwatch_ai_project_plan.md)**

---

## Getting Started

### Prerequisites

- Docker and Docker Compose

### 1. Configure your environment

```bash
cp example.env .env
# Edit .env to set ports, SSH directory, and collection interval
```

### 2. Start the system

```bash
docker compose up -d --build
```

This builds and starts:
- **NetWatch Agent / Web Dashboard** — runs nmap discovery, polls devices, ingests data, and serves the UI.
- **Kuzu Explorer** — graph database browser on port `8001`.
- **VictoriaMetrics** — time-series DB on port `8428`.
- **Chroma** — vector DB on port `8000`.

### 3. Access the Dashboard

Once the containers are running the agent begins scanning your local subnet immediately.

👉 **[http://localhost:8085](http://localhost:8085)**

The agent loops every hour (configurable via `COLLECTION_INTERVAL_SECONDS` in `.env`).

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/netwatch_ai_project_plan.md](docs/netwatch_ai_project_plan.md) | Full architecture, goals, and roadmap |
| [docs/walkthrough.md](docs/walkthrough.md) | Auto-discovery implementation walkthrough |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute code, docs, and device support |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [CHANGELOG.md](CHANGELOG.md) | Version history and change log |

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.

- 🐛 [Report a bug](https://github.com/growlf/netyeti-netwatcher/issues/new?template=bug_report.md)
- 💡 [Request a feature or device](https://github.com/growlf/netyeti-netwatcher/issues/new?template=feature_request.md)
- 💬 [Start a discussion](https://github.com/growlf/netyeti-netwatcher/discussions)

---

## Community

- **GitHub Discussions** — questions, ideas, and show-and-tells: [Discussions](https://github.com/growlf/netyeti-netwatcher/discussions)
- **Issues** — bug reports and feature requests: [Issues](https://github.com/growlf/netyeti-netwatcher/issues)

---

## License

[MIT](LICENSE)
