# NetWatch AI — Network Intelligence Assistant Project Plan v1.0
*Local LLM-powered network awareness, anomaly detection, and diagnostic assistant*

Hey everyone, I'm Garth (aka The NetYeti). Welcome to the NetWatch AI project plan! 

If you're reading this, you're probably interested in helping out or just curious about what we're building here. NetWatch AI is currently in a rapid prototype phase, and I'm super excited to share the vision with you. We are building a 100% local, self-hosted network assistant that uses LLMs as a reasoning engine to diagnose anomalies and query network topology.

Here is the breakdown of what we're trying to achieve, how the architecture is set up, and where we are going. If you see something you want to help build, jump right in!

## Our Core Goals

- **Complete network memory:** I want every device, relationship, port, VLAN, and config stored in a queryable graph so we always have a current snapshot of the network.
- **Natural language queries:** We should be able to ask in plain English: "what changed on the edge router today?" or "which hosts are talking on 8443?"
- **Proactive anomaly detection:** Let's build agents that detect deviations from baselines and surface them as pre-diagnosed alerts before things escalate.
- **Efficient context management:** We need to keep the LLM context lean via RAG. We only inject pertinent facts, never a full network dump.
- **Extensible integration layer:** We want Grafana, Slack, Obsidian, and future tools to bolt on cleanly without having to restructure our core.
- **100% local / self-hosted:** No cloud dependencies. It runs on a dedicated LXC or local server (like my 'phoenix' rig), and all data stays strictly on-premise.

> [!NOTE]
> **Our core design principle**
> The LLM is our *reasoning engine*, not the memory store. All network state lives in our structured databases. The LLM only retrieves what it needs to answer each query. This keeps responses fast, accurate, and context-efficient no matter how big the network gets.

> [!WARNING]
> **Scope of v1**
> Phase 1 focuses exclusively on the data model, storage layer, and getting one working collector agent up and running. Query capability comes in Phase 2. Proactive alerting is Phase 3. Integrations (Grafana, Slack, Obsidian) are Phase 4+. This sequencing prevents us from drowning in infrastructure debt.

## How the Architecture Works

Here's how I've broken down the layers:

**Collection Layer:**
- nmap / SNMP: Host discovery
- Node exporters: Metrics / health
- Syslog / events: Log streaming
- Custom scripts: API / SSH polls (MikroTik, Proxmox, etc.)
- Anomaly agent: Continuous watch

**Storage Layer:**
- Graph DB (Kuzu): Devices, relationships, topology, configs
- Time-series (VM): Metrics, latency, bandwidth, health
- Vector DB (Chroma): Semantic summaries, events, anomalies

**Compression Layer:**
- Summarizer / Context Compressor: Periodically generates compact NL snapshots → embeds into Chroma. This keeps our LLM context ≤4k tokens.

**Retrieval Layer:**
- LlamaIndex Query Engine: The RAG orchestrator. It routes the query → Kuzu graph query + Chroma vector search → ranked context chunks.

**Reasoning Layer:**
- Local LLM via Ollama (deepseek-r1:14b / qwen2.5-coder:14b): Receives the compact context + query, and returns a diagnosis, summary, or alert reasoning.

> [!NOTE]
> **Why are we using a graph DB?**
> Network topology is inherently relational. Kuzu lets us query things like: "find all hosts two hops from the edge router on VLAN 10 that have open port 22". That would require complex joins in SQL but is completely natural in Cypher.

> [!NOTE]
> **Context compression is our key innovation**
> A background summarizer process periodically reads fresh state and writes compressed natural-language snapshots back to Chroma. The LLM never sees raw data — only pre-digested, semantically indexed summaries retrieved by relevance.

## Our Roadmap (The Phases)

Here is how we are tackling this. If you want to contribute, check out where we are and grab a task!

### Phase 1 — Data Foundation
**Weeks 1–3 (Where we are now)**
**Goal:** Define the data model, stand up storage, and get working collection agents writing real data.
- 1.1 Design device schema: nodes (Host, Switch, Router, Service), edges (CONNECTS_TO, RUNS_ON, HAS_PORT)
- 1.2 Install and configure Kuzu in Docker
- 1.3 Install VictoriaMetrics for time-series
- 1.4 Install Chroma vector DB
- 1.5 Write nmap agent: scheduled scan → parse output → upsert Host nodes in Kuzu
- 1.6 Validate: query Kuzu to list all discovered hosts and their open ports
- 1.7 Document schema decisions

**Deliverables:** Working graph DB with device nodes populated from a real scan. Storage stack running in containers.

### Phase 2 — LLM Query Interface
**Weeks 4–6**
**Goal:** Wire LlamaIndex to the storage layer and enable basic natural language queries about the network.
- 2.1 Set up LlamaIndex with our Ollama connector 
- 2.2 Build Kuzu query tool for LlamaIndex: translates NL intent → Cypher → structured results
- 2.3 Build Chroma retriever: embed query → cosine search → top-k context chunks
- 2.4 Write summarizer agent: reads Kuzu + VictoriaMetrics → generates NL snapshot → writes to Chroma
- 2.5 Build system prompt template: topology skeleton (compact, static) + dynamic retrieved context
- 2.6 Test query battery: "list hosts", "what's on port 22", "what changed today"
- 2.7 Build simple CLI query interface

**Deliverables:** We can ask "what hosts are on VLAN 10?" and get an accurate LLM-synthesized answer from live graph data. 

### Phase 3 — Proactive Alerting
**Weeks 7–9**
**Goal:** Add the anomaly detection agent that watches for deviations and pre-diagnoses issues before they escalate.
- 3.1 Define baselines: establish rolling-window normal ranges for key metrics per host 
- 3.2 Build anomaly detector: continuously queries VictoriaMetrics, flags deviations > N sigma
- 3.3 On anomaly: auto-trigger LLM reasoning — "given this deviation on host X, what are likely causes and affected services?"
- 3.4 Write anomaly report + LLM diagnosis back to Chroma with timestamp and severity tag
- 3.5 Build "show me recent anomalies" query path through LlamaIndex
- 3.6 Tune false positive rates

**Deliverables:** The system autonomously detects and pre-diagnoses anomalies. Stored diagnoses become queryable later.

### Phase 4 — Integrations & UI
**Weeks 10–14**
**Goal:** Connect Grafana, Slack, and Obsidian. Add a web interface for interactive Q&A.
- 4.1 Grafana: build dashboards consuming VictoriaMetrics. Add annotation agent that writes LLM diagnoses as Grafana annotations
- 4.2 Slack: alerting webhook — anomalies trigger Slack message with LLM diagnosis and severity
- 4.3 Slack bot: optionally answer @netwatch queries from Slack
- 4.4 Obsidian: nightly export agent — write device inventory, recent anomalies, and topology summary to an Obsidian vault
- 4.5 Web UI: minimal chat interface (FastAPI + HTMX) for interactive query sessions
- 4.6 Additional collectors: SNMP traps, Netflow/sFlow, SSH-based config snapshots for managed switches

## Integrations

All integrations should be designed as thin adapters. They consume our existing LlamaIndex query engine or push to/from the storage layer. None of them should require changes to the core architecture.

- **Grafana (Phase 4):** Dashboards from VictoriaMetrics. 
- **Slack (Phase 4):** Webhooks for threshold alerts.
- **Obsidian (Phase 4):** Nightly exports of device inventory and topology changes.
- **Prometheus (Phase 1):** Node exporters on Linux hosts feed VictoriaMetrics.
- **Open WebUI (Phase 4):** Chat interface for interactive NL queries.
- **n8n (Phase 3):** Workflow automation for complex alert routing.
- **Netdata (Phase 2):** Per-host real-time metrics with built-in anomaly detection.
- **OpenClaw (Phase 2):** Our model gateway to swap underlying models without changing query code.

> [!NOTE]
> **Integration design rule**
> Every integration reads from or writes to the same three stores (Kuzu, VictoriaMetrics, Chroma). No integration gets direct LLM access — all LLM calls go through the LlamaIndex query engine to keep the reasoning path auditable and consistent.

## Potential Risks (And how we mitigate them)

- **[HIGH] Schema underdesign in Phase 1 causes migration pain later**
  *Mitigation:* We need to invest extra time in 1.1. Let's model for future use cases (VLAN membership, firewall rules, BGP peers) even before we collect that data. 
- **[HIGH] LLM hallucination on network facts**
  *Mitigation:* Always ground answers in retrieved data. Never rely on the LLM's training knowledge for facts about the network. Every answer must cite its Kuzu/Chroma source.
- **[MED] Anomaly alert fatigue from poorly tuned thresholds**
  *Mitigation:* We'll start with conservative thresholds (3-sigma) and tune per-device over 2 weeks of baseline data before enabling notifications. 
- **[MED] nmap / SNMP scans causing network disruption**
  *Mitigation:* Use polite timing (`nmap -T2`), schedule during low-traffic windows, and use passive ARP/CDP where possible for discovery.

## How to Get Started

*(Note: We now have a Docker Compose setup that handles this for you! Just clone the repo and run `docker compose up -d --build`)*

> [!NOTE]
> **Timeline is a guide, not a deadline**
> Each phase has a clear "done" criterion. We don't advance until the criterion is met — a solid Phase 1 foundation is worth an extra week. Phase 4 integrations can be done incrementally in any order based on what we need most.

I'm stoked to be building this with you all. Feel free to open an Issue or submit a PR if you have ideas on how to improve the architecture or want to add support for new hardware!

Cheers,  
**Garth / The NetYeti**
