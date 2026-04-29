"""
Unit tests for nmap_scanner helper functions.

All subprocess calls are mocked so that these tests run without
requiring nmap, traceroute, or an actual network interface.
"""
import sys
import os
from unittest.mock import MagicMock, patch, mock_open

import pytest

# Ensure the agent source is importable when tests run outside Docker
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "agent"))

import nmap_scanner


# ---------------------------------------------------------------------------
# get_local_subnet
# ---------------------------------------------------------------------------

def test_get_local_subnet_returns_network_cidr():
    """Happy-path: ip route returns a usable default route."""
    route_output = "default via 192.168.1.1 dev eth0 proto dhcp\n"
    addr_output = "2: eth0    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n"

    with patch("subprocess.check_output", side_effect=[route_output, addr_output]), \
         patch("os.makedirs"), \
         patch("builtins.open", mock_open()):
        result = nmap_scanner.get_local_subnet()

    assert result == "192.168.1.0/24"


def test_get_local_subnet_returns_none_on_empty_route():
    """Returns None when ip route produces no output."""
    with patch("subprocess.check_output", return_value=""):
        result = nmap_scanner.get_local_subnet()

    assert result is None


def test_get_local_subnet_returns_none_on_exception():
    """Returns None when the subprocess call raises."""
    with patch("subprocess.check_output", side_effect=OSError("nope")):
        result = nmap_scanner.get_local_subnet()

    assert result is None


# ---------------------------------------------------------------------------
# run_traceroute
# ---------------------------------------------------------------------------

def _make_traceroute_output(lines):
    header = "traceroute to 8.8.8.8 (8.8.8.8), 10 hops max\n"
    return header + "\n".join(lines) + "\n"


def test_run_traceroute_identifies_private_hops():
    """Private hops should be collected; the first public IP should be WAN."""
    traceroute_stdout = _make_traceroute_output([
        " 1  192.168.1.1  1.234 ms",
        " 2  10.0.0.1  5.678 ms",
        " 3  8.8.8.8  12.345 ms",
    ])
    mock_result = MagicMock()
    mock_result.stdout = traceroute_stdout

    with patch("subprocess.run", return_value=mock_result), \
         patch("os.makedirs"), \
         patch("builtins.open", mock_open()), \
         patch("json.dump") as mock_json_dump:
        subnets = nmap_scanner.run_traceroute()

    # Should have found two private subnets (/24 assumed)
    assert "192.168.1.0/24" in subnets
    assert "10.0.0.0/24" in subnets

    # json.dump should have been called with the hops and WAN ip
    call_args = mock_json_dump.call_args[0][0]
    assert call_args["wan_ip"] == "8.8.8.8"
    assert "192.168.1.1" in call_args["hops"]
    assert "10.0.0.1" in call_args["hops"]


def test_run_traceroute_only_private_hops():
    """When no public IP is encountered, wan_ip should remain None."""
    traceroute_stdout = _make_traceroute_output([
        " 1  10.1.1.1  1.0 ms",
        " 2  10.1.2.1  2.0 ms",
    ])
    mock_result = MagicMock()
    mock_result.stdout = traceroute_stdout

    with patch("subprocess.run", return_value=mock_result), \
         patch("os.makedirs"), \
         patch("builtins.open", mock_open()), \
         patch("json.dump") as mock_json_dump:
        nmap_scanner.run_traceroute()

    call_args = mock_json_dump.call_args[0][0]
    assert call_args["wan_ip"] is None
