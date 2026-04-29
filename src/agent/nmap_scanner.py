"""
Local network discovery using nmap and traceroute.

Identifies the active LAN subnet, performs a port scan to find network
devices, and runs a traceroute to discover upstream hops and the WAN IP.
"""
import ipaddress
import json
import logging
import os
import subprocess

import config

logger = logging.getLogger(__name__)


def get_local_subnet() -> str | None:
    """
    Determine the local LAN subnet (CIDR notation) by inspecting the
    default route and the IP address of the corresponding interface.

    Returns ``None`` when the subnet cannot be determined.
    """
    try:
        route_out = subprocess.check_output("ip route | grep default", shell=True, text=True)
        if not route_out:
            return None
        parts = route_out.strip().split()
        if 'dev' not in parts:
            return None
        iface = parts[parts.index('dev') + 1]

        if 'via' in parts:
            gateway_ip = parts[parts.index('via') + 1]
            os.makedirs(config.FACTS_DIR, exist_ok=True)
            with open(os.path.join(config.FACTS_DIR, "gateway.txt"), "w") as f:
                f.write(gateway_ip)

        addr_out = subprocess.check_output(f"ip -o -f inet addr show {iface}", shell=True, text=True)
        cidr = addr_out.strip().split()[3]

        # Normalise to network address (e.g. 192.168.1.10/24 → 192.168.1.0/24)
        net = ipaddress.IPv4Interface(cidr).network
        return str(net)
    except Exception as e:
        logger.error("[Nmap] Error finding local subnet: %s", e)
        return None


def run_traceroute() -> list:
    """
    Run a traceroute to ``TRACEROUTE_TARGET`` and return a list of private
    upstream subnet CIDRs discovered along the path.

    The WAN IP (first public address seen) and the ordered list of private
    hops are written to ``<FACTS_DIR>/traceroute.json``.

    .. note::
        Upstream subnets are assumed to be ``/24``.  This is a common
        homelab/ISP configuration, but may be incorrect for more complex
        network topologies.
    """
    target = config.TRACEROUTE_TARGET
    wan_ip_override = config.ROUTER_WAN_IP
    logger.info("[Nmap] Running traceroute to %s to discover upstream networks...", target)

    cmd = ["traceroute", "-n", "-m", "10", "-w", "2", "-q", "1", target]
    result = subprocess.run(cmd, capture_output=True, text=True)

    hops = []
    subnets = []
    wan_ip = wan_ip_override if wan_ip_override else None

    for line in result.stdout.split('\n')[1:]:
        parts = line.strip().split()
        if len(parts) >= 2:
            hop_ip = parts[1]
            if hop_ip == "*":
                continue
            try:
                ip_obj = ipaddress.IPv4Address(hop_ip)
                if ip_obj.is_private:
                    hops.append(hop_ip)
                    # NOTE: Assuming /24 for upstream networks — this may not
                    # be accurate for all ISP or enterprise configurations.
                    net = str(ipaddress.IPv4Interface(f"{hop_ip}/24").network)
                    if net not in subnets:
                        subnets.append(net)
                else:
                    if not wan_ip:
                        wan_ip = hop_ip
                    hops.append(wan_ip)
                    break  # Stop at the first public IP
            except ValueError:
                pass

    os.makedirs(config.FACTS_DIR, exist_ok=True)
    with open(os.path.join(config.FACTS_DIR, "traceroute.json"), "w") as f:
        json.dump({"hops": hops, "wan_ip": wan_ip}, f)

    logger.info("[Nmap] Traceroute found upstream hops: %s", hops)
    logger.info("[Nmap] Discovered upstream subnets: %s", subnets)
    if wan_ip:
        logger.info("[Nmap] WAN IP identified as: %s", wan_ip)

    return subnets


def run_scan() -> None:
    """
    Discover all active hosts on the local LAN (and nearby upstream subnets)
    using nmap.  Results are written to ``<FACTS_DIR>/nmap_discovery.xml``.
    """
    logger.info("[Nmap] Starting automatic local network discovery...")
    subnet = get_local_subnet()

    extra_subnets = run_traceroute()
    all_subnets = []
    if subnet:
        all_subnets.append(subnet)
    for s in extra_subnets:
        if s not in all_subnets:
            all_subnets.append(s)

    if not all_subnets:
        logger.warning("[Nmap] Could not determine any subnets to scan. Skipping auto-discovery.")
        return

    logger.info(
        "[Nmap] Scanning subnets: %s. Checking for open ports 22, 80, 443, 5380, 8006, 8291...",
        all_subnets,
    )
    output_file = os.path.join(config.FACTS_DIR, "nmap_discovery.xml")

    cmd = ["nmap", "-p", "22,80,443,5380,8006,8291"] + all_subnets + ["-oX", output_file]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        logger.info("[Nmap] Discovery complete. Results saved to %s", output_file)
    else:
        logger.error("[Nmap] Scan failed: %s", result.stderr)


if __name__ == "__main__":
    run_scan()
