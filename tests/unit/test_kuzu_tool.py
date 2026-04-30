"""
Unit tests for kuzu_tool helper functions and the LlamaIndex FunctionTool.
"""
import sys
import os
import json
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "agent"))

# Stub llama_index modules before importing kuzu_tool to avoid network calls
import types

# Build minimal stubs for llama_index hierarchy
llama_index_stub = types.ModuleType("llama_index")
llama_index_core_stub = types.ModuleType("llama_index.core")
llama_index_tools_stub = types.ModuleType("llama_index.core.tools")

class _FakeFunctionTool:
    def __init__(self, fn, name, description):
        self.fn = fn
        self.metadata = MagicMock()
        self.metadata.name = name
        self.metadata.description = description

    @classmethod
    def from_defaults(cls, fn, name, description):
        return cls(fn=fn, name=name, description=description)

llama_index_tools_stub.FunctionTool = _FakeFunctionTool
llama_index_core_stub.tools = llama_index_tools_stub

sys.modules.setdefault("llama_index", llama_index_stub)
sys.modules.setdefault("llama_index.core", llama_index_core_stub)
sys.modules.setdefault("llama_index.core.tools", llama_index_tools_stub)

# Stub llm_connector so no real LLM is needed
llm_connector_stub = types.ModuleType("llm_connector")
llm_connector_stub.get_llm = MagicMock(return_value=None)
sys.modules["llm_connector"] = llm_connector_stub

# Stub kuzu
kuzu_stub = types.ModuleType("kuzu")
kuzu_stub.Database = MagicMock()
kuzu_stub.Connection = MagicMock()
sys.modules.setdefault("kuzu", kuzu_stub)

# Stub config
config_stub = types.ModuleType("config")
config_stub.DB_PATH = "/tmp/test_netwatch.kuzu"
sys.modules["config"] = config_stub

import kuzu_tool  # noqa: E402


# ---------------------------------------------------------------------------
# get_db_schema
# ---------------------------------------------------------------------------

def test_get_db_schema_contains_nodes():
    schema = kuzu_tool.get_db_schema()
    assert "Host" in schema
    assert "Router" in schema
    assert "Interface" in schema
    assert "Service" in schema


def test_get_db_schema_contains_relationships():
    schema = kuzu_tool.get_db_schema()
    assert "HAS_INTERFACE" in schema
    assert "HAS_PORT" in schema
    assert "CONNECTS_TO" in schema


# ---------------------------------------------------------------------------
# execute_kuzu_query
# ---------------------------------------------------------------------------

def _make_result(rows):
    result = MagicMock()
    call_count = [0]
    total = len(rows)

    def has_next_side_effect():
        return call_count[0] < total

    def get_next_side_effect():
        val = rows[call_count[0]]
        call_count[0] += 1
        return val

    result.has_next.side_effect = has_next_side_effect
    result.get_next.side_effect = get_next_side_effect
    return result


def test_execute_kuzu_query_returns_json():
    mock_db = MagicMock()
    mock_conn = MagicMock()
    mock_result = _make_result([["host1", "192.168.1.1"]])
    mock_conn.execute.return_value = mock_result

    with patch("kuzu_tool.kuzu.Database", return_value=mock_db), \
         patch("kuzu_tool.kuzu.Connection", return_value=mock_conn):
        result = kuzu_tool.execute_kuzu_query("MATCH (h:Host) RETURN h.hostname, h.ip")
    parsed = json.loads(result)
    assert isinstance(parsed, list)
    assert parsed[0] == ["host1", "192.168.1.1"]


def test_execute_kuzu_query_blocks_write_keywords():
    for dangerous in ["CREATE (n:Host)", "DELETE n", "MERGE (n)", "SET n.x=1", "DROP TABLE Host"]:
        result = kuzu_tool.execute_kuzu_query(dangerous)
        parsed = json.loads(result)
        assert "error" in parsed
        assert "Only MATCH" in parsed["error"]


def test_execute_kuzu_query_returns_error_on_exception():
    mock_db = MagicMock()
    mock_conn = MagicMock()
    mock_conn.execute.side_effect = RuntimeError("connection failed")

    with patch("kuzu_tool.kuzu.Database", return_value=mock_db), \
         patch("kuzu_tool.kuzu.Connection", return_value=mock_conn):
        result = kuzu_tool.execute_kuzu_query("MATCH (h:Host) RETURN h")
    parsed = json.loads(result)
    assert "error" in parsed
    assert "connection failed" in parsed["error"]


# ---------------------------------------------------------------------------
# load_few_shots
# ---------------------------------------------------------------------------

def test_load_few_shots_returns_default_examples(tmp_path):
    result = kuzu_tool.load_few_shots()
    assert "MATCH" in result
    assert "Question:" in result
    assert "Cypher:" in result


def test_load_few_shots_loads_custom_file(tmp_path):
    custom = [
        {"nl": "Find all hosts", "cypher": "MATCH (h:Host) RETURN h.hostname;"}
    ]
    custom_path = tmp_path / "kuzu_few_shots.json"
    custom_path.write_text(json.dumps(custom))

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", MagicMock(return_value=open(str(custom_path)))):
        result = kuzu_tool.load_few_shots()

    assert "Find all hosts" in result
    assert "MATCH (h:Host)" in result


# ---------------------------------------------------------------------------
# kuzu_query_tool (LlamaIndex FunctionTool)
# ---------------------------------------------------------------------------

def test_kuzu_query_tool_is_defined():
    assert hasattr(kuzu_tool, "kuzu_query_tool")


def test_kuzu_query_tool_has_correct_name():
    assert kuzu_tool.kuzu_query_tool.metadata.name == "execute_network_cypher_query"


def test_kuzu_query_tool_description_mentions_cypher():
    desc = kuzu_tool.kuzu_query_tool.metadata.description
    assert "Cypher" in desc or "cypher" in desc.lower()


def test_kuzu_query_tool_wraps_execute_function():
    assert kuzu_tool.kuzu_query_tool.fn is kuzu_tool.execute_kuzu_query
