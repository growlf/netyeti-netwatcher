# NetWatch AI — Network Intelligence Assistant

**NetWatch AI** is a local LLM-powered network awareness, anomaly detection, and diagnostic assistant. It aims to maintain a complete, queryable graph of your network, detect proactive anomalies, and provide natural language interactions without relying on external cloud services.

## Overview

> [!WARNING]
> **Project Status: Prototype / Rapid Development**
> NetWatch AI is currently in active prototype development. Features, data structures, and the user interface are changing rapidly. 

### Current Hardware Support
Currently, NetWatch AI only supports direct API/SSH polling for devices we have implemented so far:
- **MikroTik RouterOS** (v6 and v7 via SSH/API)
- **Proxmox VE** (via Proxmoxer API)
- **Technitium DNS**

### Planned Features
We are actively building out the following features:
- **Local and Remote LLM Support**: Query your network topology using natural language (LlamaIndex).
- **Interactive Network Mapping**: Visual graphs to explore nodes and links.
- **Alerting & Charting**: Grafana integrations and alerting for anomalies.
- **Enhanced Telemetry**: Expanding support to ubiquiti, cisco, and more.

> [!TIP]
> **Have a device you want supported?** 
> Please open an Issue and submit a feature request on GitHub! We will prioritize hardware based on community requests.

The system is built on a 100% local, self-hosted architecture consisting of:
- **Kuzu**: An embeddable Graph Database for mapping devices, interfaces, and network topology.
- **VictoriaMetrics**: A time-series database for monitoring latency, bandwidth, and health metrics.
- **Chroma**: A vector database for storing semantic summaries and events.
- **Telemetry Agents**: Python agents and Ansible (`get_facts.yml`) for host node and interface discovery.

For a detailed breakdown of the architecture, goals, and project phases, please refer to the comprehensive project plan:
👉 **[docs/netwatch_ai_project_plan.md](docs/netwatch_ai_project_plan.md)**

---

## Getting Started (Phase 1)

Follow these steps to spin up the local infrastructure and start ingesting network telemetry.

### Prerequisites
* Docker and Docker Compose

### 1. Configure the Agent

Create an Ansible inventory file in the `./config` directory (it will be mapped into the agent container).

```bash
mkdir -p config
cat <<EOF > config/inventory.yml
localhost ansible_connection=local
# Add your network devices here
EOF
```

### 2. Start the System

NetWatch AI uses Docker Compose to run everything (Data Stores and the Collection Agent) seamlessly in containers.

```bash
docker compose up -d --build
```

*This will build and start:*
- **NetWatch Agent**: The Python/Ansible collector container that regularly runs `get_facts.yml` and ingests facts into Kuzu.
- **Kuzu**: Graph DB with persistent storage mapped to `./kuzu-data`.
- **VictoriaMetrics**: Time-series DB on port `8428`.
- **Chroma**: Vector DB on port `8000`.

The agent will automatically loop and collect telemetry every hour (configurable via `COLLECTION_INTERVAL_SECONDS` in docker-compose.yml), keeping your local host completely clean!

---

## Next Steps

Check the **[Project Plan](docs/netwatch_ai_project_plan.html)** for information on the upcoming phases, which include connecting the LlamaIndex query engine, setting up proactive anomaly alerting, and integrating with Grafana and Slack.
