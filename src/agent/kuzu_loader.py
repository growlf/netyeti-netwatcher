import os
import json
import glob
import kuzu
import xml.etree.ElementTree as ET

# Configuration
DB_PATH = '/data/netwatch.kuzu'
FACTS_DIR = './collected_facts'

def init_db(conn):
    """
    Initialize the graph database schema if it doesn't already exist.
    According to the NetWatch project plan Phase 1, we need nodes for 
    Hosts, Switches, Routers, Services and relationships.
    """
    schema_queries = [
        "CREATE NODE TABLE Host(id STRING, hostname STRING, ip STRING, os STRING, PRIMARY KEY (id))",
        "CREATE NODE TABLE Router(id STRING, hostname STRING, ip STRING, os STRING, PRIMARY KEY (id))",
        "CREATE NODE TABLE Interface(id STRING, name STRING, mac_address STRING, ipv4 STRING, PRIMARY KEY (id))",
        "CREATE NODE TABLE Service(id STRING, name STRING, port INT64, state STRING, PRIMARY KEY (id))",
        "CREATE REL TABLE HAS_INTERFACE(FROM Host TO Interface)",
        "CREATE REL TABLE HAS_INTERFACE(FROM Router TO Interface)",
        "CREATE REL TABLE HAS_PORT(FROM Host TO Service)",
        "CREATE REL TABLE HAS_PORT(FROM Router TO Service)",
        "CREATE REL TABLE CONNECTS_TO(FROM Host TO Host)",
        "CREATE REL TABLE CONNECTS_TO(FROM Host TO Router)",
        "CREATE REL TABLE CONNECTS_TO(FROM Router TO Host)",
        "CREATE REL TABLE CONNECTS_TO(FROM Router TO Router)"
    ]
    
    for query in schema_queries:
        try:
            conn.execute(query)
            print(f"[Schema] Created: {query.split('(')[0]}")
        except RuntimeError as e:
            # If the table already exists, Kuzu throws a RuntimeError. We can safely ignore it.
            if "already exists" not in str(e).lower():
                print(f"[Error] Failed to execute {query}: {e}")

def load_ansible_facts(conn):
    """
    Read the JSON output from get_facts.yml and ingest it into the Kuzu graph database.
    """
    if not os.path.exists(FACTS_DIR):
        print(f"[Warning] Facts directory '{FACTS_DIR}' not found. Run the Ansible playbook first.")
        return

    json_files = glob.glob(os.path.join(FACTS_DIR, '*.json'))
    if not json_files:
        print(f"[Warning] No JSON files found in {FACTS_DIR}.")
        return

    print(f"[Info] Found {len(json_files)} fact files. Starting ingestion...")

    for filepath in json_files:
        with open(filepath, 'r') as f:
            try:
                facts = json.load(f)
            except json.JSONDecodeError:
                print(f"[Error] Could not parse JSON in {filepath}")
                continue
        
        # The Ansible get_facts.yml saves the facts dictionary directly
        hostname = facts.get('ansible_hostname', os.path.basename(filepath).replace('_facts.json', ''))
        ip = facts.get('ansible_default_ipv4', {}).get('address', 'Unknown')
        os_family = facts.get('ansible_os_family', 'Unknown')
        
        is_router = 'routeros' in os_family.lower() or 'cisco' in os_family.lower()
        table = "Router" if is_router else "Host"
        
        host_id = f"host_{hostname}"
        
        # Kuzu MERGE command handles UPSERT logic
        host_query = f"""
        MERGE (h:{table} {{id: '{host_id}'}})
        ON CREATE SET h.hostname = '{hostname}', h.ip = '{ip}', h.os = '{os_family}'
        ON MATCH SET h.hostname = '{hostname}', h.ip = '{ip}', h.os = '{os_family}'
        """
        
        try:
            conn.execute(host_query)
            print(f"[Ingest] Upserted Host: {hostname} ({ip})")
        except Exception as e:
            print(f"[Error] Failed to upsert Host {hostname}: {e}")
            continue

        # Ingest Interfaces
        interfaces = facts.get('ansible_interfaces', [])
        for iface in interfaces:
            if iface == 'lo':  # Skip loopback
                continue
                
            iface_facts = facts.get(f'ansible_{iface.replace("-", "_")}', {})
            mac = iface_facts.get('macaddress', 'Unknown')
            ipv4 = iface_facts.get('ipv4', {}).get('address', 'Unknown')
            iface_id = f"{host_id}_iface_{iface}"
            
            iface_query = f"""
            MERGE (i:Interface {{id: '{iface_id}'}})
            ON CREATE SET i.name = '{iface}', i.mac_address = '{mac}', i.ipv4 = '{ipv4}'
            ON MATCH SET i.name = '{iface}', i.mac_address = '{mac}', i.ipv4 = '{ipv4}'
            """
            
            rel_query = f"""
            MATCH (h:{table} {{id: '{host_id}'}}), (i:Interface {{id: '{iface_id}'}})
            MERGE (h)-[r:HAS_INTERFACE]->(i)
            """
            try:
                conn.execute(iface_query)
                conn.execute(rel_query)
            except Exception as e:
                print(f"[Error] Failed to upsert Interface {iface} for {hostname}: {e}")

def load_nmap_facts(conn):
    """
    Read the XML output from nmap_scanner.py and ingest discovered hosts into Kuzu.
    """
    filepath = os.path.join(FACTS_DIR, 'nmap_discovery.xml')
    if not os.path.exists(filepath):
        return
        
    print(f"[Info] Found nmap discovery file. Starting ingestion...")
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except Exception as e:
        print(f"[Error] Failed to parse nmap xml: {e}")
        return
        
    traceroute_file = os.path.join(FACTS_DIR, 'traceroute.json')
    hops = []
    wan_ip = None
    if os.path.exists(traceroute_file):
        with open(traceroute_file, 'r') as f:
            trace_data = json.load(f)
            hops = trace_data.get('hops', [])
            wan_ip = trace_data.get('wan_ip')
            
    gateway_file = os.path.join(FACTS_DIR, 'gateway.txt')
    gateway_ip = None
    if os.path.exists(gateway_file):
        with open(gateway_file, 'r') as f:
            gateway_ip = f.read().strip()
            
    # Build a dictionary of subnet -> gateway_ip
    subnet_gateways = {}
    for hop in hops:
        parts = hop.split('.')
        if len(parts) == 4 and hop.endswith('.1'):
            subnet_base = f"{parts[0]}.{parts[1]}.{parts[2]}"
            subnet_gateways[subnet_base] = hop
            
    if gateway_ip:
        parts = gateway_ip.split('.')
        if len(parts) == 4:
            subnet_base = f"{parts[0]}.{parts[1]}.{parts[2]}"
            subnet_gateways[subnet_base] = gateway_ip
            
    count = 0
    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
            
        ip = "Unknown"
        mac = "Unknown"
        vendor = "Unknown"
        hostname = ""
        
        for address in host.findall('address'):
            addr_type = address.get('addrtype')
            if addr_type == 'ipv4':
                ip = address.get('addr')
            elif addr_type == 'mac':
                mac = address.get('addr')
                vendor = address.get('vendor', 'Unknown')
                
        hostnames_node = host.find('hostnames')
        if hostnames_node is not None:
            hostname_node = hostnames_node.find('hostname')
            if hostname_node is not None:
                hostname = hostname_node.get('name')
                
        if not hostname:
            hostname = f"host_{ip.replace('.', '_')}"
            
        # Use MAC as ID if available, else IP
        host_id = f"mac_{mac.replace(':', '')}" if mac != "Unknown" else f"ip_{ip.replace('.', '')}"
        
        is_router = (ip in hops) or (ip in subnet_gateways.values()) or ("Routerboard" in vendor or "MikroTik" in vendor)
        table = "Router" if is_router else "Host"
        
        host_query = f"""
        MERGE (h:{table} {{id: '{host_id}'}})
        ON CREATE SET h.hostname = '{hostname}', h.ip = '{ip}', h.os = 'Unknown'
        ON MATCH SET h.ip = '{ip}'
        """
        try:
            conn.execute(host_query)
            count += 1
        except Exception as e:
            print(f"[Error] Failed to upsert nmap host {ip}: {e}")
            continue
            
        if mac != "Unknown":
            iface_id = f"{host_id}_primary"
            iface_query = f"""
            MERGE (i:Interface {{id: '{iface_id}'}})
            ON CREATE SET i.name = '{vendor}', i.mac_address = '{mac}', i.ipv4 = '{ip}'
            ON MATCH SET i.mac_address = '{mac}', i.ipv4 = '{ip}'
            """
            rel_query = f"""
            MATCH (h:{table} {{id: '{host_id}'}}), (i:Interface {{id: '{iface_id}'}})
            MERGE (h)-[r:HAS_INTERFACE]->(i)
            """
            try:
                conn.execute(iface_query)
                conn.execute(rel_query)
            except Exception as e:
                print(f"[Error] Failed to upsert nmap interface for {ip}: {e}")
    
    # Connect hosts to their respective subnet gateway
    # Wait, they might be routers or hosts! Kuzu MATCH (h) without label matches both? No, MATCH (h:Host) matches only Host.
    # To match ANY node type, we omit the label: MATCH (h), (gw)
    for subnet_base, gw_ip in subnet_gateways.items():
        gw_query = f"""
        MATCH (h), (gw)
        WHERE (h:Host OR h:Router) AND (gw:Host OR gw:Router)
        AND h.ip STARTS WITH '{subnet_base}.' 
        AND h.ip <> '{gw_ip}' 
        AND gw.ip = '{gw_ip}' 
        MERGE (h)-[:CONNECTS_TO]->(gw)
        """
        try:
            conn.execute(gw_query)
        except Exception as e:
            pass

    # Process Proxmox Networks and Rewire Topology
    proxmox_guests = {}
    import glob
    for pfile in glob.glob("/app/collected_facts/proxmox_*.json"):
        proxmox_ip = os.path.basename(pfile).replace("proxmox_", "").replace(".json", "")
        try:
            with open(pfile, "r") as f:
                pdata = json.load(f)
                for guest in pdata.get("guests", []):
                    for g_ip in guest.get("ips", []):
                        proxmox_guests[g_ip] = proxmox_ip
        except Exception:
            pass
            
    for guest_ip, proxmox_ip in proxmox_guests.items():
        try:
            conn.execute(f"MATCH (guest)-[r:CONNECTS_TO]->(gw) WHERE (guest:Host OR guest:Router) AND guest.ip = '{guest_ip}' AND (gw:Host OR gw:Router) AND gw.ip <> '{proxmox_ip}' DELETE r")
            conn.execute(f"MATCH (guest), (prox) WHERE (guest:Host OR guest:Router) AND guest.ip = '{guest_ip}' AND (prox:Host OR prox:Router) AND prox.ip = '{proxmox_ip}' MERGE (guest)-[:CONNECTS_TO]->(prox)")
        except Exception:
            pass


    # Ensure all hops exist as Router Host nodes
    for hop in hops:
        host_id = f"ip_{hop.replace('.', '')}"
        query = f"""
        MERGE (h:Router {{id: '{host_id}'}})
        ON CREATE SET h.hostname = 'router_{hop}', h.ip = '{hop}', h.os = 'Unknown'
        ON MATCH SET h.ip = '{hop}'
        """
        try:
            conn.execute(query)
        except Exception as e:
            pass
            
    # Link local gateway to first hop if it's different
    if gateway_ip and hops and gateway_ip != hops[0]:
        try:
            conn.execute(f"MATCH (src), (dst) WHERE (src:Host OR src:Router) AND (dst:Host OR dst:Router) AND src.ip = '{gateway_ip}' AND dst.ip = '{hops[0]}' MERGE (src)-[:CONNECTS_TO]->(dst)")
        except Exception:
            pass

    # Link the hops sequentially
    for i in range(len(hops) - 1):
        try:
            conn.execute(f"MATCH (src), (dst) WHERE (src:Host OR src:Router) AND (dst:Host OR dst:Router) AND src.ip = '{hops[i]}' AND dst.ip = '{hops[i+1]}' MERGE (src)-[:CONNECTS_TO]->(dst)")
        except Exception:
            pass
            
    if hops:
        print(f"[Ingest] Linked upstream traceroute hops: {' -> '.join(hops)}")
        
    # Add WAN Interface
    if wan_ip and hops:
        outermost_router_ip = hops[-1]
        host_id = f"ip_{outermost_router_ip.replace('.', '')}"
        iface_id = f"{host_id}_wan_external"
        
        iface_query = f"""
        MERGE (i:Interface {{id: '{iface_id}'}})
        ON CREATE SET i.name = 'WAN_External', i.mac_address = 'Unknown', i.ipv4 = '{wan_ip}'
        ON MATCH SET i.ipv4 = '{wan_ip}'
        """
        rel_query = f"""
        MATCH (h:Router {{ip: '{outermost_router_ip}'}}), (i:Interface {{id: '{iface_id}'}})
        MERGE (h)-[:HAS_INTERFACE]->(i)
        """
        try:
            conn.execute(iface_query)
            conn.execute(rel_query)
            print(f"[Ingest] Attached WAN Public IP {wan_ip} to router {outermost_router_ip}")
        except Exception as e:
            print(f"[Error] Failed to attach WAN interface: {e}")

    print(f"[Ingest] Processed {count} active hosts from Nmap.")

def main():
    print(f"Connecting to Kuzu Graph Database at {DB_PATH}...")
    
    # Ensure the directory exists before initializing Kuzu
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    db = kuzu.Database(DB_PATH)
    conn = kuzu.Connection(db)
    
    try:
        init_db(conn)
        load_nmap_facts(conn)
        load_ansible_facts(conn)
    finally:
        conn.close()
        db.close()
    
    print("[Success] Data ingestion complete. Close the connection to release DB locks.")

if __name__ == '__main__':
    main()
