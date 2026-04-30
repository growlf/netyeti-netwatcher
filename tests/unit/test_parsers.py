import os
import sys

# Ensure the agent source directory is on the path when running tests outside Docker
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "agent"))

from parsers import parse_routeros_print  # noqa: E402


def test_parse_routeros_print_empty():
    raw_output = "Flags: X - disabled, I - invalid, D - dynamic\n"
    result = parse_routeros_print(raw_output)
    assert len(result) == 0

def test_parse_routeros_print_valid_leases():
    raw_output = """
Flags: X - disabled, I - invalid, D - dynamic
 0 D server=defconf mac-address=AA:BB:CC:DD:EE:FF address=192.168.88.254 host-name="Android"
     status=bound expires-after=1h5m2s last-seen=5m2s active-address=192.168.88.254 active-mac-address=AA:BB:CC:DD:EE:FF
     active-client-id="1:AA:BB:CC:DD:EE:FF" active-server=defconf

 1   server=defconf mac-address=11:22:33:44:55:66 address=192.168.88.100 host-name="TV"
     status=bound expires-after=23h59m59s last-seen=1s active-address=192.168.88.100 active-mac-address=11:22:33:44:55:66
     active-client-id="1:11:22:33:44:55:66" active-server=defconf
"""
    result = parse_routeros_print(raw_output)

    assert len(result) == 2

    # Assert first device
    assert result[0]['mac-address'] == 'AA:BB:CC:DD:EE:FF'
    assert result[0]['address'] == '192.168.88.254'
    assert result[0]['host-name'] == 'Android'

    # Assert second device
    assert result[1]['mac-address'] == '11:22:33:44:55:66'
    assert result[1]['address'] == '192.168.88.100'
    assert result[1]['host-name'] == 'TV'
