"""
Parsing utilities for network device output formats.
"""
import re


def parse_routeros_print(text: str) -> list:
    """
    Parse the human-readable output of a RouterOS ``/print detail`` command
    into a list of dictionaries.

    Each numbered entry in the output becomes one dictionary.  Flags at the
    start of each entry (e.g. ``R`` for running, ``X`` for disabled) are
    stored under the keys ``running`` and ``disabled``.

    Lines beginning with ``;;;`` (comments) are silently ignored.
    """
    items = []
    current_item = {}
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
            if current_item:
                items.append(current_item)
                current_item = {}
            continue
        m = re.match(r'^(\d+)\s+([A-Z\s]*)\s+(.*)', line)
        if m:
            if current_item:
                items.append(current_item)
                current_item = {}
            flags = m.group(2).strip()
            if 'R' in flags:
                current_item['running'] = 'true'
            if 'X' in flags:
                current_item['disabled'] = 'true'
            line = m.group(3)
        elif line.startswith(';;;'):
            continue

        pairs = re.findall(r'([\w-]+)=(?:"([^"]*)"|(\S+))', line)
        for k, v1, v2 in pairs:
            current_item[k] = v1 if v1 else v2
    if current_item:
        items.append(current_item)
    return items
