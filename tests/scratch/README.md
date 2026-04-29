# Scratch / Exploratory Tests

This directory contains **one-off exploratory scripts** used during development to test
library APIs and device connectivity.  These are **not** part of the automated test suite
and are not run by pytest.

They require real network hardware (MikroTik routers, Paramiko SSH targets, etc.) to be
useful and are kept here for reference only.

| File | Purpose |
|------|---------|
| `parse_test.py` | Manual scratch pad for parsing RouterOS output |
| `test_api.py` | Exploratory test for routeros-api library connectivity |
| `test_librouteros.py` | Exploratory test for librouteros library |
| `test_paramiko.py` | Exploratory test for Paramiko SSH connectivity |
| `test_paramiko_42.py` | Variant of the above |

For proper unit tests, see [`../unit/`](../unit/).
