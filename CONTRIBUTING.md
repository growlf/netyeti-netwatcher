# Contributing to NetWatch AI

First of all — thank you for your interest in contributing! NetWatch AI is a community project and every contribution, no matter how small, is valued.

## Ways to Contribute

- 🐛 **Report a bug** — [open a Bug Report](https://github.com/growlf/netyeti-netwatcher/issues/new?template=bug_report.md)
- 💡 **Request a feature or new device** — [open a Feature Request](https://github.com/growlf/netyeti-netwatcher/issues/new?template=feature_request.md)
- 🔧 **Fix a bug or implement a feature** — see the workflow below
- 📝 **Improve documentation** — typos, clarity, and examples are always welcome

---

## Development Setup

### Prerequisites

- Python 3.10+
- Docker and Docker Compose
- `git`

### Clone and install

```bash
git clone https://github.com/growlf/netyeti-netwatcher.git
cd netyeti-netwatcher

# Install runtime + dev dependencies
pip install -r src/agent/requirements.txt -r requirements-dev.txt
```

### Run the tests

```bash
# From the repo root
PYTHONPATH=src/agent pytest tests/unit/ -v
```

### Lint

```bash
ruff check src/agent/ tests/unit/
```

### Run the full stack locally

```bash
cp example.env .env
# Edit .env as needed
docker compose up -d --build
# Dashboard: http://localhost:8085
```

---

## Pull Request Workflow

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. **Make your changes** and add or update tests as appropriate.
3. **Run tests and lint** to make sure everything passes.
4. **Commit** with a clear, descriptive message:
   ```
   feat: add Ubiquiti UniFi device collector
   fix: handle missing MAC address in nmap output
   docs: clarify Proxmox token authentication setup
   ```
5. **Push** your branch and open a Pull Request against `main`.
6. Fill in the PR template. A maintainer will review and provide feedback.

### Commit Message Convention

We loosely follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use for |
|--------|---------|
| `feat:` | New features |
| `fix:` | Bug fixes |
| `docs:` | Documentation only |
| `refactor:` | Code restructuring (no behaviour change) |
| `test:` | Adding or fixing tests |
| `chore:` | Build, CI, dependency updates |

---

## Code Style

- Python code is linted with [ruff](https://docs.astral.sh/ruff/).
- Line length is 110 characters.
- Use descriptive variable names and add docstrings to public functions.
- Do **not** commit secrets, credentials, API keys, or `.env` files.

---

## Adding a New Device Collector

1. Create `src/agent/<vendor>_collector.py`.
2. Follow the pattern of `proxmox_collector.py`:
   - Read credentials from `config.HOST_VARS_DIR`.
   - Write output JSON to `config.FACTS_DIR`.
3. Import and call your collector from `agent.py` in the main loop.
4. Add unit tests in `tests/unit/`.
5. Document the new device in the README under "Current Hardware Support".

---

## Questions?

Open a [GitHub Discussion](https://github.com/growlf/netyeti-netwatcher/discussions) or ping **@growlf** in an issue.
