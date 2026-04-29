import re
def parse_routeros_print(text):
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
            if 'R' in flags: current_item['running'] = 'true'
            if 'X' in flags: current_item['disabled'] = 'true'
            line = m.group(3)
        elif line.startswith(';;;'):
            continue
        pairs = re.findall(r'([\w-]+)=(?:"([^"]*)"|(\S+))', line)
        for k, v1, v2 in pairs:
            current_item[k] = v1 if v1 else v2
    if current_item:
        items.append(current_item)
    return items

text = """
 0 D   address=192.168.42.152 mac-address=DE:AD:BE:EF:00:01 client-id="1:de:ad:be:ef:0:1" 
       address-lists="" server=dhcp1 dhcp-option="" status=bound expires-after=1h 
       last-seen=1m1s active-address=192.168.42.152 active-mac-address=DE:AD:BE:EF:00:01 
       active-client-id="1:de:ad:be:ef:0:1" active-server=dhcp1 host-name="TV" 
"""
print(parse_routeros_print(text))
