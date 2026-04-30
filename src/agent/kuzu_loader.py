"""
Ingest network discovery data into the Kuzu graph database.

Data sources:
  - Ansible JSON fact files  (``collected_facts/<hostname>_facts.json``)
  - nmap XML output          (``collected_facts/nmap_discovery.xml``)
  - Proxmox guest JSON files (``collected_facts/proxmox_<ip>.json``)
"""
import glob
import json
import logging
import os
import xml.etree.ElementTree as ET

import kuzu

import config

logger = logging.getLogger(__name__)

DB_PATH = config.DB_PATH
FACTS_DIR = config.FACTS_DIR

# ---------------------------------------------------------------------------
# Allowed node-table names (used to prevent label injection)
# ---------------------------------------------------------------------------
_VALID_TABLES = frozenset({"Host", "Router"})


def _sanitize_table(table: str) -> str:
    """Return *table* if it is a known node label, otherwise raise ValueError."""
    if table not in _VALID_TABLES:
        raise ValueError(f"Invalid node table name: {table!r}")
    return table


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db(conn: kuzu.Connection) -> None:
    """
    Create graph schema tables if they do not already exist.

    Kuzu raises a RuntimeError when a table already exists, which we
    silently ignore so that this function is safe to call on every startup.
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
        "CREATE REL TABLE CONNECTS_TO(FROM Router TO Router)",
    ]

    for query in schema_queries:
        try:
            conn.execute(query)
            logger.info("[Schema] Created: %s", query.split('(')[0])
        except RuntimeError as e:
            if "already exists" not in str(e).lower():
                logger.error("[Schema] Failed to execute %s: %s", query, e)


# ---------------------------------------------------------------------------
# Ansible fact ingestion
# ---------------------------------------------------------------------------

def load_ansible_facts(conn: kuzu.Connection) -> None:
    """
    Read Ansible JSON output files and upsert their data into Kuzu.
    """
    if not os.path.exists(FACTS_DIR):
        logger.warning("[Ansible] Facts directory '%s' not found. Run the Ansible playbook first.", FACTS_DIR)
        return

    json_files = glob.glob(os.path.join(FACTS_DIR, '*.json'))
    if not json_files:
        logger.warning("[Ansible] No JSON files found in %s.", FACTS_DIR)
        return

    logger.info("[Ansible] Found %d fact files. Starting ingestion...", len(json_files))

    for filepath in json_files:
        with open(filepath) as f:
            try:
                facts = json.load(f)
            except json.JSONDecodeError:
                logger.error("[Ansible] Could not parse JSON in %s", filepath)
                continue

        hostname = facts.get('ansible_hostname', os.path.basename(filepath).replace('_facts.json', ''))
        ip = facts.get('ansible_default_ipv4', {}).get('address', 'Unknown')
        os_family = facts.get('ansible_os_family', 'Unknown')

        is_router = 'routeros' in os_family.lower() or 'cisco' in os_family.lower()
        table = _sanitize_table("Router" if is_router else "Host")
        host_id = f"host_{hostname}"

        host_query = f"""
        MERGE (h:{table} {{id: $id}})
        ON CREATE SET h.hostname = $hostname, h.ip = $ip, h.os = $os
        ON MATCH SET h.hostname = $hostname, h.ip = $ip, h.os = $os
        """
        try:
            conn.execute(host_query, parameters={"id": host_id, "hostname": hostname, "ip": ip, "os": os_family})
            logger.info("[Ansible] Upserted %s: %s (%s)", table, hostname, ip)
        except Exception as e:
            logger.error("[Ansible] Failed to upsert %s %s: %s", table, hostname, e)
            continue

        # Ingest Interfaces
        for iface in facts.get('ansible_interfaces', []):
            if iface == 'lo':
                continue

            iface_facts = facts.get(f'ansible_{iface.replace("-", "_")}', {})
            mac = iface_facts.get('macaddress', 'Unknown')
            ipv4 = iface_facts.get('ipv4', {}).get('address', 'Unknown')
            iface_id = f"{host_id}_iface_{iface}"

            iface_query = """
            MERGE (i:Interface {id: $id})
            ON CREATE SET i.name = $name, i.mac_address = $mac, i.ipv4 = $ipv4
            ON MATCH SET i.name = $name, i.mac_address = $mac, i.ipv4 = $ipv4
            """
            rel_query = f"""
            MATCH (h:{table} {{id: $host_id}}), (i:Interface {{id: $iface_id}})
            MERGE (h)-[r:HAS_INTERFACE]->(i)
            """
            try:
                conn.execute(iface_query, parameters={"id": iface_id, "name": iface, "mac": mac, "ipv4": ipv4})
                conn.execute(rel_query, parameters={"host_id": host_id, "iface_id": iface_id})
            except Exception as e:
                logger.error("[Ansible] Failed to upsert Interface %s for %s: %s", iface, hostname, e)


# ---------------------------------------------------------------------------
# nmap fact ingestion
# ---------------------------------------------------------------------------

def load_nmap_facts(conn: kuzu.Connection) -> None:
    """
    Parse the nmap XML discovery file and upsert discovered hosts into Kuzu.
    """
    filepath = os.path.join(FACTS_DIR, 'nmap_discovery.xml')
    if not os.path.exists(filepath):
        return

    logger.info("[Nmap] Found nmap discovery file. Starting ingestion...")
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except Exception as e:
        logger.error("[Nmap] Failed to parse nmap XML: %s", e)
        return

    traceroute_file = os.path.join(FACTS_DIR, 'traceroute.json')
    hops = []
    wan_ip = None
    if os.path.exists(traceroute_file):
        with open(traceroute_file) as f:
            trace_data = json.load(f)
            hops = trace_data.get('hops', [])
            wan_ip = trace_data.get('wan_ip')

    gateway_file = os.path.join(FACTS_DIR, 'gateway.txt')
    gateway_ip = None
    if os.path.exists(gateway_file):
        with open(gateway_file) as f:
            gateway_ip = f.read().strip()

    # Map subnet base (first three octets) to gateway IP
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
                hostname = hostname_node.get('name', '')

        if not hostname:
            hostname = f"host_{ip.replace('.', '_')}"

        # Prefer MAC as stable identifier; fall back to IP
        host_id = f"mac_{mac.replace(':', '')}" if mac != "Unknown" else f"ip_{ip.replace('.', '')}"

        is_router = (
            ip in hops
            or ip in subnet_gateways.values()
            or ("Routerboard" in vendor or "MikroTik" in vendor)
        )
        table = _sanitize_table("Router" if is_router else "Host")

        host_query = f"""
        MERGE (h:{table} {{id: $id}})
        ON CREATE SET h.hostname = $hostname, h.ip = $ip, h.os = 'Unknown'
        ON MATCH SET h.ip = $ip
        """
        try:
            conn.execute(host_query, parameters={"id": host_id, "hostname": hostname, "ip": ip})
            count += 1
        except Exception as e:
            logger.error("[Nmap] Failed to upsert nmap host %s: %s", ip, e)
            continue

        if mac != "Unknown":
            iface_id = f"{host_id}_primary"
            iface_query = """
            MERGE (i:Interface {id: $id})
            ON CREATE SET i.name = $name, i.mac_address = $mac, i.ipv4 = $ipv4
            ON MATCH SET i.mac_address = $mac, i.ipv4 = $ipv4
            """
            rel_query = f"""
            MATCH (h:{table} {{id: $host_id}}), (i:Interface {{id: $iface_id}})
            MERGE (h)-[r:HAS_INTERFACE]->(i)
            """
            try:
                conn.execute(iface_query, parameters={"id": iface_id, "name": vendor, "mac": mac, "ipv4": ip})
                conn.execute(rel_query, parameters={"host_id": host_id, "iface_id": iface_id})
            except Exception as e:
                logger.error("[Nmap] Failed to upsert interface for %s: %s", ip, e)

    # Connect hosts to their subnet gateway
    for subnet_base, gw_ip in subnet_gateways.items():
        gw_query = """
        MATCH (h), (gw)
        WHERE (h:Host OR h:Router) AND (gw:Host OR gw:Router)
        AND h.ip STARTS WITH $prefix
        AND h.ip <> $gw_ip
        AND gw.ip = $gw_ip
        MERGE (h)-[:CONNECTS_TO]->(gw)
        """
        try:
            conn.execute(gw_query, parameters={"prefix": f"{subnet_base}.", "gw_ip": gw_ip})
        except Exception as e:
            logger.debug("[Nmap] Could not link subnet %s to gateway %s: %s", subnet_base, gw_ip, e)

    # Re-wire Proxmox guest nodes to point to the Proxmox host
    for pfile in glob.glob(os.path.join(FACTS_DIR, "proxmox_*.json")):
        proxmox_ip = os.path.basename(pfile).replace("proxmox_", "").replace(".json", "")
        try:
            with open(pfile) as f:
                pdata = json.load(f)
                for guest in pdata.get("guests", []):
                    for g_ip in guest.get("ips", []):
                        try:
                            conn.execute(
                                "MATCH (guest)-[r:CONNECTS_TO]->(gw) "
                                "WHERE (guest:Host OR guest:Router) AND guest.ip = $g_ip "
                                "AND (gw:Host OR gw:Router) AND gw.ip <> $proxmox_ip "
                                "DELETE r",
                                parameters={"g_ip": g_ip, "proxmox_ip": proxmox_ip},
                            )
                            conn.execute(
                                "MATCH (guest), (prox) "
                                "WHERE (guest:Host OR guest:Router) AND guest.ip = $g_ip "
                                "AND (prox:Host OR prox:Router) AND prox.ip = $proxmox_ip "
                                "MERGE (guest)-[:CONNECTS_TO]->(prox)",
                                parameters={"g_ip": g_ip, "proxmox_ip": proxmox_ip},
                            )
                        except Exception as e:
                            logger.debug("[Proxmox] Could not rewire guest %s → %s: %s", g_ip, proxmox_ip, e)
        except Exception as e:
            logger.warning("[Proxmox] Could not read %s: %s", pfile, e)

    # Ensure all traceroute hops exist as Router nodes
    for hop in hops:
        host_id = f"ip_{hop.replace('.', '')}"
        query = """
        MERGE (h:Router {id: $id})
        ON CREATE SET h.hostname = $hostname, h.ip = $ip, h.os = 'Unknown'
        ON MATCH SET h.ip = $ip
        """
        try:
            conn.execute(query, parameters={"id": host_id, "hostname": f"router_{hop}", "ip": hop})
        except Exception as e:
            logger.debug("[Nmap] Could not upsert hop router %s: %s", hop, e)

    # Link local gateway → first traceroute hop
    if gateway_ip and hops and gateway_ip != hops[0]:
        try:
            conn.execute(
                "MATCH (src), (dst) "
                "WHERE (src:Host OR src:Router) AND (dst:Host OR dst:Router) "
                "AND src.ip = $src AND dst.ip = $dst "
                "MERGE (src)-[:CONNECTS_TO]->(dst)",
                parameters={"src": gateway_ip, "dst": hops[0]},
            )
        except Exception as e:
            logger.debug("[Nmap] Could not link gateway to first hop: %s", e)

    # Link traceroute hops sequentially
    for i in range(len(hops) - 1):
        try:
            conn.execute(
                "MATCH (src), (dst) "
                "WHERE (src:Host OR src:Router) AND (dst:Host OR dst:Router) "
                "AND src.ip = $src AND dst.ip = $dst "
                "MERGE (src)-[:CONNECTS_TO]->(dst)",
                parameters={"src": hops[i], "dst": hops[i + 1]},
            )
        except Exception as e:
            logger.debug("[Nmap] Could not link hop %s → %s: %s", hops[i], hops[i + 1], e)

    if hops:
        logger.info("[Nmap] Linked upstream traceroute hops: %s", " -> ".join(hops))

    # Attach WAN interface to outermost router
    if wan_ip and hops:
        outermost_router_ip = hops[-1]
        host_id = f"ip_{outermost_router_ip.replace('.', '')}"
        iface_id = f"{host_id}_wan_external"

        iface_query = """
        MERGE (i:Interface {id: $id})
        ON CREATE SET i.name = 'WAN_External', i.mac_address = 'Unknown', i.ipv4 = $wan_ip
        ON MATCH SET i.ipv4 = $wan_ip
        """
        rel_query = """
        MATCH (h:Router {ip: $router_ip}), (i:Interface {id: $iface_id})
        MERGE (h)-[:HAS_INTERFACE]->(i)
        """
        try:
            conn.execute(iface_query, parameters={"id": iface_id, "wan_ip": wan_ip})
            conn.execute(rel_query, parameters={"router_ip": outermost_router_ip, "iface_id": iface_id})
            logger.info("[Nmap] Attached WAN Public IP %s to router %s", wan_ip, outermost_router_ip)
        except Exception as e:
            logger.error("[Nmap] Failed to attach WAN interface: %s", e)

    logger.info("[Nmap] Processed %d active hosts from Nmap.", count)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logger.info("Connecting to Kuzu Graph Database at %s...", DB_PATH)

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

    logger.info("[Success] Data ingestion complete.")


if __name__ == '__main__':
    main()
