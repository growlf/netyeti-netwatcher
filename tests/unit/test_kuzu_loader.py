"""
Unit tests for kuzu_loader helper functions.
"""
import sys
import os
import types
import tempfile
import textwrap
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "agent"))

# Stub kuzu and kuzu_db before importing kuzu_loader
kuzu_stub = types.ModuleType("kuzu")
kuzu_stub.Database = MagicMock()
kuzu_stub.Connection = MagicMock()
sys.modules.setdefault("kuzu", kuzu_stub)

kuzu_db_stub = types.ModuleType("kuzu_db")
kuzu_db_stub.get_connection = MagicMock()
sys.modules["kuzu_db"] = kuzu_db_stub

# Provide a minimal config stub so kuzu_loader can be imported standalone
config_stub = types.ModuleType("config")
config_stub.DB_PATH = "/tmp/test.kuzu"
config_stub.FACTS_DIR = "/tmp/test_facts"
sys.modules.setdefault("config", config_stub)

from kuzu_loader import _sanitize_table, _VPN_PORT_MAP, _ingest_nmap_services  # noqa: E402


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


# ---------------------------------------------------------------------------
# _VPN_PORT_MAP
# ---------------------------------------------------------------------------

def test_vpn_port_map_contains_wireguard():
    assert _VPN_PORT_MAP[51820] == "wireguard"


def test_vpn_port_map_contains_ikev2():
    assert _VPN_PORT_MAP[500] == "ikev2"
    assert _VPN_PORT_MAP[4500] == "ikev2"


def test_vpn_port_map_contains_openvpn():
    assert _VPN_PORT_MAP[1194] == "openvpn"


def test_vpn_port_map_contains_pptp():
    assert _VPN_PORT_MAP[1723] == "pptp"


# ---------------------------------------------------------------------------
# _ingest_nmap_services
# ---------------------------------------------------------------------------

def _make_nmap_xml(ip, ports):
    """Build a minimal nmap XML string with the given open ports.

    ``ports`` is a list of ``(portid, protocol, state, service_name)`` tuples.
    """
    port_xml = ""
    for portid, protocol, state, svcname in ports:
        port_xml += f"""
        <port protocol="{protocol}" portid="{portid}">
          <state state="{state}" reason="syn-ack"/>
          <service name="{svcname}"/>
        </port>"""

    return textwrap.dedent(f"""<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up" reason="echo-reply"/>
        <address addr="{ip}" addrtype="ipv4"/>
        <ports>{port_xml}
        </ports>
      </host>
    </nmaprun>""")


def test_ingest_nmap_services_known_vpn_port(tmp_path):
    """WireGuard port 51820 should produce a Service node named 'wireguard'."""
    xml = _make_nmap_xml("10.0.0.5", [(51820, "udp", "open|filtered", "unknown")])
    nmap_file = tmp_path / "nmap_vpn_udp.xml"
    nmap_file.write_text(xml)

    mock_conn = MagicMock()
    count = _ingest_nmap_services(mock_conn, str(nmap_file))

    assert count == 1
    # First execute call is the MERGE for the Service node
    svc_call_kwargs = mock_conn.execute.call_args_list[0][1]["parameters"]
    assert svc_call_kwargs["name"] == "wireguard"
    assert svc_call_kwargs["port"] == 51820


def test_ingest_nmap_services_generic_port(tmp_path):
    """A non-VPN open port should use the nmap service name."""
    xml = _make_nmap_xml("10.0.0.6", [(22, "tcp", "open", "ssh")])
    nmap_file = tmp_path / "nmap_discovery.xml"
    nmap_file.write_text(xml)

    mock_conn = MagicMock()
    count = _ingest_nmap_services(mock_conn, str(nmap_file))

    assert count == 1
    svc_call_kwargs = mock_conn.execute.call_args_list[0][1]["parameters"]
    assert svc_call_kwargs["name"] == "ssh"
    assert svc_call_kwargs["port"] == 22


def test_ingest_nmap_services_skips_closed_ports(tmp_path):
    """Closed ports must not produce Service nodes."""
    xml = _make_nmap_xml("10.0.0.7", [
        (80, "tcp", "closed", "http"),
        (443, "tcp", "filtered", "https"),
    ])
    nmap_file = tmp_path / "nmap_discovery.xml"
    nmap_file.write_text(xml)

    mock_conn = MagicMock()
    count = _ingest_nmap_services(mock_conn, str(nmap_file))

    assert count == 0
    mock_conn.execute.assert_not_called()


def test_ingest_nmap_services_skips_down_hosts(tmp_path):
    """Hosts with status != 'up' must be ignored."""
    xml = textwrap.dedent("""<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="down" reason="no-response"/>
        <address addr="10.0.0.8" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh"/>
          </port>
        </ports>
      </host>
    </nmaprun>""")
    nmap_file = tmp_path / "nmap_discovery.xml"
    nmap_file.write_text(xml)

    mock_conn = MagicMock()
    count = _ingest_nmap_services(mock_conn, str(nmap_file))

    assert count == 0


def test_ingest_nmap_services_returns_zero_on_bad_file(tmp_path):
    """A malformed XML file must not raise; it should return 0."""
    bad_file = tmp_path / "bad.xml"
    bad_file.write_text("this is not xml <<<")

    mock_conn = MagicMock()
    count = _ingest_nmap_services(mock_conn, str(bad_file))

    assert count == 0
    mock_conn.execute.assert_not_called()


def test_ingest_nmap_services_ikev2_dual_ports(tmp_path):
    """Both port 500 and 4500 should be identified as 'ikev2'."""
    xml = _make_nmap_xml("10.0.0.9", [
        (500, "udp", "open|filtered", "isakmp"),
        (4500, "udp", "open|filtered", "ipsec-nat-t"),
    ])
    nmap_file = tmp_path / "nmap_vpn.xml"
    nmap_file.write_text(xml)

    mock_conn = MagicMock()
    count = _ingest_nmap_services(mock_conn, str(nmap_file))

    assert count == 2
    # execute calls follow the pattern: [Service MERGE, HAS_PORT MERGE, Service MERGE, HAS_PORT MERGE, ...]
    # Indices 0 and 2 are the two Service MERGE calls; each carries the 'name' parameter.
    names = [
        mock_conn.execute.call_args_list[i][1]["parameters"]["name"]
        for i in (0, 2)
    ]
    assert all(n == "ikev2" for n in names)

