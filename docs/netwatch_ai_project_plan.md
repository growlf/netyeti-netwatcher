# NetWatch AI — Network Intelligence Assistant Project Plan v1.0
Local LLM-powered network awareness, anomaly detection, and diagnostic assistant

## Goals

- **Complete network memory:** Every device, relationship, port, VLAN, and config stored in a queryable graph — always current.
- **Natural language queries:** Ask in plain English: "what changed on the edge router today?" or "which hosts are talking on 8443?"
- **Proactive anomaly detection:** Agents detect deviations from baseline and surface them as pre-diagnosed alerts before escalation.
- **Efficient context management:** LLM context stays lean via RAG — only pertinent facts injected, never the full network dump.
- **Extensible integration layer:** Grafana, Slack, Obsidian, and future tools bolt on cleanly without restructuring the core.
- **100% local / self-hosted:** No cloud dependency. Runs on phoenix or a dedicated LXC. All data stays on-premise.

> [!NOTE]
> **Design principle**
> The LLM is the *reasoning engine*, not the memory store. All network state lives in structured databases — the LLM retrieves only what's needed to answer each query. This keeps responses fast, accurate, and context-efficient regardless of network size.

> [!WARNING]
> **Scope of v1**
> Phase 1 focuses exclusively on the data model, storage layer, and one working collector agent. Query capability comes in Phase 2. Proactive alerting is Phase 3. Integrations (Grafana, Slack, Obsidian) are Phase 4+. This sequencing prevents infra debt.

## Architecture

**Collection Layer:**
- nmap / SNMP: Host discovery
- Node exporters: Metrics / health
- Syslog / events: Log streaming
- Custom scripts: API / SSH polls
- Anomaly agent: Continuous watch

**Storage Layer:**
- Graph DB (Kuzu): Devices, relationships, topology, configs
- Time-series (VM): Metrics, latency, bandwidth, health
- Vector DB (Chroma): Semantic summaries, events, anomalies

**Compression Layer:**
- Summarizer / Context Compressor: Periodically generates compact NL snapshots → embeds into Chroma · Keeps LLM context ≤4k tokens

**Retrieval Layer:**
- LlamaIndex Query Engine: RAG orchestrator · routes query → Kuzu graph query + Chroma vector search → ranked context chunks

**Reasoning Layer:**
- Local LLM via Ollama (deepseek-r1:14b / qwen2.5-coder:14b): Receives compact context + query · Returns diagnosis, summary, or alert reasoning

> [!NOTE]
> **Why a graph DB?**
> Network topology is inherently relational. Kuzu lets you query: "find all hosts two hops from the edge router on VLAN 10 that have open port 22" — a query that would require complex joins in SQL but is natural in Cypher.

> [!NOTE]
> **Context compression is the key innovation**
> A background summarizer process periodically reads fresh state and writes compressed natural-language snapshots back to Chroma. The LLM never sees raw data — only pre-digested, semantically indexed summaries retrieved by relevance.

## Phases

### Phase 1 — Data Foundation
**Weeks 1–3**
**Goal:** Define the data model, stand up storage, and get one working collection agent writing real data.
- 1.1 Design device schema: nodes (Host, Switch, Router, Service), edges (CONNECTS_TO, RUNS_ON, HAS_PORT)
- 1.2 Install and configure Kuzu (embeddable graph DB) in Docker/LXC on phoenix
- 1.3 Install VictoriaMetrics for time-series (lighter than InfluxDB, Prometheus-compatible)
- 1.4 Install Chroma vector DB, configure persistence volume
- 1.5 Write nmap agent: scheduled scan → parse output → upsert Host nodes in Kuzu
- 1.6 Validate: query Kuzu to list all discovered hosts and their open ports
- 1.7 Document schema decisions in Obsidian vault (netwatch/schema.md)

**Deliverables:** Working graph DB with device nodes populated from a real scan. Schema documented. Storage stack running in containers.

### Phase 2 — LLM Query Interface
**Weeks 4–6**
**Goal:** Wire LlamaIndex to the storage layer and enable basic natural language queries about the network.
- 2.1 Set up LlamaIndex with Ollama connector (point at existing OpenClaw endpoint port 18789)
- 2.2 Build Kuzu query tool for LlamaIndex: translates NL intent → Cypher → structured results
- 2.3 Build Chroma retriever: embed query → cosine search → top-k context chunks
- 2.4 Write summarizer agent: reads Kuzu + VictoriaMetrics → generates NL snapshot → writes to Chroma
- 2.5 Build system prompt template: topology skeleton (compact, static) + dynamic retrieved context
- 2.6 Test query battery: "list hosts", "what's on port 22", "what changed today", "is X reachable from Y"
- 2.7 Build simple CLI query interface (Python click or bare argparse)

**Deliverables:** Can ask "what hosts are on VLAN 10?" and get an accurate LLM-synthesized answer from live graph data. Context stays under 4k tokens per query.

### Phase 3 — Proactive Alerting
**Weeks 7–9**
**Goal:** Add the anomaly detection agent that watches for deviations and pre-diagnoses issues before they escalate.
- 3.1 Define baselines: establish rolling-window normal ranges for key metrics per host (latency, packet loss, port state)
- 3.2 Build anomaly detector: continuously queries VictoriaMetrics, flags deviations > N sigma
- 3.3 On anomaly: auto-trigger LLM reasoning — "given this deviation on host X, what are likely causes and affected services?"
- 3.4 Write anomaly report + LLM diagnosis back to Chroma with timestamp and severity tag
- 3.5 Build "show me recent anomalies" query path through LlamaIndex
- 3.6 Tune false positive rate: adjust thresholds and add device-specific baseline overrides

**Deliverables:** System autonomously detects and pre-diagnoses anomalies. Stored diagnoses queryable later: "what happened on the switch last Tuesday?"

### Phase 4 — Integrations & UI
**Weeks 10–14**
**Goal:** Connect Grafana, Slack, and Obsidian. Add a chat web interface for interactive Q&A.
- 4.1 Grafana: build dashboards consuming VictoriaMetrics. Add annotation agent that writes LLM diagnoses as Grafana annotations
- 4.2 Slack: alerting webhook — anomalies above threshold trigger Slack message with LLM diagnosis and severity
- 4.3 Slack bot: optionally answer @netwatch queries from Slack (thin wrapper around LlamaIndex query engine)
- 4.4 Obsidian: nightly export agent — write device inventory, recent anomalies, and topology summary to Obsidian vault as markdown
- 4.5 Web UI: minimal chat interface (FastAPI + HTMX or Open WebUI fork) for interactive query sessions
- 4.6 Additional collectors: SNMP traps, Netflow/sFlow, SSH-based config snapshots for managed switches

**Deliverables:** Full operational loop: collect → store → summarize → detect → alert → visualize → document. Multiple query surfaces (CLI, Slack, web UI, Obsidian).

## Integrations

All integrations are designed as thin adapters — they consume the existing LlamaIndex query engine or push to/from the storage layer. None require changes to the core architecture.

- **Grafana (Phase 4):** Dashboards from VictoriaMetrics. Annotation agent writes LLM diagnoses as Grafana annotations, so anomalies show in-context on metric graphs.
- **Slack (Phase 4):** Webhook for threshold alerts with LLM diagnosis. Optional bot for @netwatch queries direct from Slack channels.
- **Obsidian (Phase 4):** Nightly export: device inventory, anomaly history, topology changes → markdown files in vault. Living runbook auto-generated.
- **Prometheus (Phase 1):** Node exporters on Linux hosts feed VictoriaMetrics (Prometheus-compatible scrape endpoint). Zero additional config needed.
- **Open WebUI (Phase 4):** Chat interface for interactive NL queries. Can be forked or used as-is with custom system prompt wired to LlamaIndex backend.
- **n8n (Phase 3):** Workflow automation for complex alert routing — multi-channel notification, escalation logic, incident ticketing without custom code.
- **Netdata (Phase 2):** Per-host real-time metrics with built-in anomaly detection. Can augment VictoriaMetrics baseline data or replace node exporters.
- **OpenClaw (Phase 2):** Already running at :18789. LlamaIndex connects here. Acts as model gateway — swap underlying model without changing query code.

> [!NOTE]
> **Integration design rule**
> Every integration reads from or writes to the same three stores (Kuzu, VictoriaMetrics, Chroma). No integration gets direct LLM access — all LLM calls go through the LlamaIndex query engine. This keeps the reasoning path auditable and consistent.

## Risks

- **[HIGH] Schema underdesign in Phase 1 causes migration pain later**
  Mitigation: invest extra time in 1.1. Model for future use cases (VLAN membership, firewall rules, BGP peers) even before you collect that data. Schema changes in graph DBs are less painful than SQL but still disruptive.
- **[HIGH] LLM hallucination on network facts**
  Mitigation: always ground answers in retrieved data, never rely on LLM training knowledge for facts about your network. Add a citation step: every answer must cite its Kuzu/Chroma source.
- **[MED] Anomaly alert fatigue from poorly tuned thresholds**
  Mitigation: start with conservative thresholds (3-sigma), tune per-device over 2 weeks of baseline data before enabling notifications. Add severity tiers.
- **[MED] Context window management complexity grows with network size**
  Mitigation: the summarizer/compressor layer is the correct solution. Invest in it in Phase 2. Hard-cap retrieved context at 3500 tokens, leaving buffer for system prompt and output.
- **[MED] nmap / SNMP scans causing network disruption**
  Mitigation: use nmap -T2 (polite timing), schedule during low-traffic windows, whitelist in firewall rules, use passive ARP/CDP where possible for discovery.
- **[LOW] deepseek-r1:14b too slow for real-time anomaly reasoning on phoenix**
  Mitigation: anomaly reasoning is async (not user-facing), so latency is acceptable. For interactive queries, use qwen2.5-coder which is faster. Profile in Phase 2 and switch models if needed.
- **[LOW] Kuzu lack of community resources compared to Neo4j**
  Mitigation: Kuzu's Cypher dialect is close to Neo4j's. If blockers arise, Neo4j Community Edition is a drop-in replacement. Design the query layer with an abstraction that allows swapping.

## Timeline

- **Phase 1:** Data foundation (Weeks 1–3)
- **Phase 2:** Query interface (Weeks 4–6)
- **Phase 3:** Proactive alerts (Weeks 7–9)
- **Phase 4:** Integrations (Weeks 10–14)

**Recommended starting stack (Phase 1 day 1)**
```bash
docker run -d --name kuzu -v ./kuzu-data:/data kuzudb/kuzu:latest
docker run -d --name victoria -p 8428:8428 -v ./vm-data:/storage victoriametrics/victoria-metrics
docker run -d --name chroma -p 8000:8000 -v ./chroma-data:/chroma/chroma chromadb/chroma
pip install kuzu llama-index chromadb llamaindex-llms-ollama
```

> [!NOTE]
> **Timeline is a guide, not a deadline**
> Each phase has a clear "done" criterion. Don't advance until the criterion is met — a solid Phase 1 foundation is worth an extra week. Phase 4 integrations can be done incrementally in any order based on what you need most.
