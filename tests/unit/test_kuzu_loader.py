"""
Unit tests for kuzu_loader helper functions.
"""
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "agent"))

from kuzu_loader import _sanitize_table


def test_sanitize_table_accepts_host():
    assert _sanitize_table("Host") == "Host"


def test_sanitize_table_accepts_router():
    assert _sanitize_table("Router") == "Router"


def test_sanitize_table_rejects_unknown():
    with pytest.raises(ValueError, match="Invalid node table name"):
        _sanitize_table("Service")


def test_sanitize_table_rejects_injection():
    """Ensure a Cypher-injection attempt is rejected."""
    with pytest.raises(ValueError):
        _sanitize_table("Host}); DROP TABLE Host;//")
