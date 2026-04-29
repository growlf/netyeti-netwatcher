"""
Background collection agent loop for NetWatch AI.

Runs as a daemon thread inside the FastAPI process and periodically:
  1. Discovers LAN devices via nmap  (when AUTO_DISCOVERY is enabled)
  2. Updates the Ansible inventory from the nmap results
  3. Runs the Ansible fact-collection playbook
  4. Collects Proxmox guest information
  5. Ingests everything into the Kuzu graph database
"""
import logging
import os
import subprocess
import time
import ipaddress
import xml.etree.ElementTree as ET

import nmap_scanner
import kuzu_loader
import config

logger = logging.getLogger(__name__)


def update_inventory_from_nmap(inventory_path: str) -> None:
    """
    Build an Ansible inventory YAML file from a previously-saved nmap XML
    discovery result.  Devices on the local subnet go into ``sandbox_lan``;
    anything upstream goes into ``upstream_lan``.
    """
    nmap_xml = os.path.join(config.FACTS_DIR, "nmap_discovery.xml")
    if not os.path.exists(nmap_xml):
        logger.info("[Agent] No nmap discovery file found at %s, skipping inventory update.", nmap_xml)
        return

    logger.info("[Agent] Automatically updating Ansible inventory from Nmap discovery...")
    try:
        tree = ET.parse(nmap_xml)
        root = tree.getroot()

        local_subnet_str = nmap_scanner.get_local_subnet()
        local_net = ipaddress.IPv4Network(local_subnet_str) if local_subnet_str else None

        sandbox_devices = {}
        upstream_devices = {}

        for host in root.findall('host'):
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue

            ip = None
            vendor = None
            for address in host.findall('address'):
                if address.get('addrtype') == 'ipv4':
                    ip = address.get('addr')
                elif address.get('addrtype') == 'mac':
                    vendor = address.get('vendor', '')

            if ip:
                is_mikrotik = bool(vendor and ("Routerboard" in vendor or "MikroTik" in vendor))
                if not is_mikrotik:
                    for port in host.findall('.//port'):
                        if port.get('portid') == '8291':
                            state = port.find('state')
                            if state is not None and state.get('state') == 'open':
                                is_mikrotik = True
                                break

                os_type = "community.routeros.routeros" if is_mikrotik else None

                if local_net and ipaddress.IPv4Address(ip) in local_net:
                    sandbox_devices[ip] = os_type
                else:
                    upstream_devices[ip] = os_type

        os.makedirs(os.path.dirname(inventory_path), exist_ok=True)
        with open(inventory_path, "w") as f:
            f.write("---\n")
            f.write("all:\n")
            f.write("  hosts:\n")
            f.write("    localhost:\n")
            f.write("      ansible_connection: local\n")

            if sandbox_devices or upstream_devices:
                f.write("  children:\n")

            if sandbox_devices:
                f.write("    sandbox_lan:\n")
                f.write("      hosts:\n")
                for ip, os_type in sandbox_devices.items():
                    f.write(f"        {ip}:\n")
                    if os_type:
                        f.write(f"          ansible_network_os: {os_type}\n")

            if upstream_devices:
                f.write("    upstream_lan:\n")
                f.write("      hosts:\n")
                for ip, os_type in upstream_devices.items():
                    f.write(f"        {ip}:\n")
                    if os_type:
                        f.write(f"          ansible_network_os: {os_type}\n")

        logger.info(
            "[Agent] Updated inventory: %d sandbox devices, %d upstream devices.",
            len(sandbox_devices),
            len(upstream_devices),
        )
    except Exception as e:
        logger.error("[Agent] Error updating inventory: %s", e)


def agent_loop() -> None:
    """
    Main collection loop.  Runs indefinitely, sleeping between cycles.
    """
    interval = config.COLLECTION_INTERVAL_SECONDS
    logger.info("[Agent Loop] Started. Interval configured for %d seconds.", interval)

    time.sleep(5)

    while True:
        try:
            logger.info("[Agent] Starting telemetry collection...")

            if config.AUTO_DISCOVERY:
                nmap_scanner.run_scan()

            inventory_path = os.path.join(config.CONFIG_DIR, "inventory.yml")
            if config.AUTO_DISCOVERY:
                update_inventory_from_nmap(inventory_path)
            elif not os.path.exists(inventory_path):
                os.makedirs(config.CONFIG_DIR, exist_ok=True)
                with open(inventory_path, "w") as f:
                    f.write("localhost ansible_connection=local\n")

            cmd = ["ansible-playbook", "-i", inventory_path, "get_facts.yml"]
            logger.info("[Agent] Running command: %s", " ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.warning("[Agent] Ansible playbook encountered errors:\n%s\n%s", result.stdout, result.stderr)
            else:
                logger.info("[Agent] Ansible telemetry collection completed.")

            logger.info("[Agent] Starting Proxmox collection...")
            try:
                import proxmox_collector
                proxmox_collector.collect_proxmox_facts()
            except Exception as e:
                logger.error("[Agent] Error running Proxmox collection: %s", e)

            logger.info("[Agent] Starting Kuzu ingestion...")
            try:
                kuzu_loader.main()
            except Exception as e:
                logger.error("[Agent] Error running Kuzu loader: %s", e)

            logger.info("[Agent] Cycle complete.")
        except Exception as e:
            logger.error("[Agent] Error during collection cycle: %s", e)

        logger.info("[Agent] Sleeping for %d seconds...", interval)
        time.sleep(interval)
