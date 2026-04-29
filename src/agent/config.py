"""
Centralized configuration and path constants for the NetWatch agent.

All paths can be overridden with environment variables, making the
application easier to test locally and deploy in different environments.
"""
import os

# Directory containing this file (src/agent/) — used to derive defaults
# so the application works both inside the Docker container and in local tests.
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Data directories ---
FACTS_DIR = os.environ.get("FACTS_DIR", "/app/collected_facts")
DB_PATH = os.environ.get("DB_PATH", "/data/netwatch.kuzu")

# --- Application directories ---
CONFIG_DIR = os.environ.get("CONFIG_DIR", "/app/config")
HOST_VARS_DIR = os.path.join(CONFIG_DIR, "host_vars")

# Templates are shipped as source files — default to their location relative
# to this module so tests work without needing a /app directory.
TEMPLATES_DIR = os.environ.get("TEMPLATES_DIR", os.path.join(_AGENT_DIR, "templates"))

# --- SSH ---
SSH_DIR = os.environ.get("SSH_DIR", "/root/.ssh")

# --- Collection settings ---
COLLECTION_INTERVAL_SECONDS = int(os.environ.get("COLLECTION_INTERVAL_SECONDS", "3600"))
AUTO_DISCOVERY = os.environ.get("AUTO_DISCOVERY", "false").lower() == "true"
TRACEROUTE_TARGET = os.environ.get("TRACEROUTE_TARGET", "8.8.8.8")
ROUTER_WAN_IP = os.environ.get("ROUTER_WAN_IP", "").strip()
