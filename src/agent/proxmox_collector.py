"""
Collect VM/LXC inventory from Proxmox VE nodes and save to the facts directory.
"""
import json
import logging
import os

import proxmoxer
import yaml

import config as netwatch_config

logger = logging.getLogger(__name__)


def collect_proxmox_facts() -> None:
    logger.info("[ProxmoxCollector] Starting Proxmox data collection...")
    config_dir = netwatch_config.HOST_VARS_DIR
    facts_dir = netwatch_config.FACTS_DIR
    os.makedirs(facts_dir, exist_ok=True)

    if not os.path.exists(config_dir):
        logger.info("[ProxmoxCollector] No host_vars directory found at %s.", config_dir)
        return

    for f in os.listdir(config_dir):
        if not f.endswith(".yml"):
            continue

        ip = f.replace(".yml", "")
        filepath = os.path.join(config_dir, f)

        try:
            with open(filepath) as cf:
                creds = yaml.safe_load(cf)
        except Exception as e:
            logger.debug("[ProxmoxCollector] Could not read %s: %s", filepath, e)
            continue

        user = creds.get('ansible_user', '')
        password = creds.get('ansible_password', '')

        # Determine if it's a Proxmox host by checking the username format
        if not ("!" in user or "@pam" in user or "@pve" in user):
            continue

        logger.info("[ProxmoxCollector] Connecting to Proxmox at %s...", ip)
        try:
            if "ansible_ssh_private_key_file" in creds:
                proxmox = proxmoxer.ProxmoxAPI(
                    ip,
                    user=user,
                    backend='ssh_paramiko',
                    private_key_file=creds['ansible_ssh_private_key_file'],
                )
            elif "!" in user:
                user_part, token_name = user.split("!")
                logger.warning(
                    "[ProxmoxCollector] Connecting to %s with verify_ssl=False — "
                    "certificate verification is disabled.",
                    ip,
                )
                proxmox = proxmoxer.ProxmoxAPI(
                    ip,
                    user=user_part,
                    token_name=token_name,
                    token_value=password,
                    verify_ssl=False,
                )
            else:
                logger.warning(
                    "[ProxmoxCollector] Connecting to %s with verify_ssl=False — "
                    "certificate verification is disabled.",
                    ip,
                )
                proxmox = proxmoxer.ProxmoxAPI(ip, user=user, password=password, verify_ssl=False)

            nodes = proxmox.nodes.get()
            if not nodes:
                continue

            node_name = nodes[0]['node']

            # Collect VMs and LXCs with IP addresses
            guests = []

            # LXC containers
            try:
                lxcs = proxmox.nodes(node_name).lxc.get()
                for lxc in lxcs:
                    vmid = lxc.get("vmid")
                    lxc_config = proxmox.nodes(node_name).lxc(vmid).config.get()
                    # Extract IP from net0, net1, etc.
                    # Format: name=eth0,bridge=vmbr0,ip=192.168.1.100/24,...
                    ips = []
                    for k, v in lxc_config.items():
                        if k.startswith("net") and "ip=" in v:
                            for part in v.split(","):
                                if part.startswith("ip="):
                                    ip_val = part.split("=")[1].split("/")[0]
                                    if ip_val and ip_val != "dhcp":
                                        ips.append(ip_val)
                    if ips:
                        guests.append({"vmid": vmid, "name": lxc.get("name"), "type": "lxc", "ips": ips})
            except Exception as e:
                logger.error("[ProxmoxCollector] Error fetching LXCs for %s: %s", ip, e)

            # QEMU virtual machines
            try:
                vms = proxmox.nodes(node_name).qemu.get()
                for vm in vms:
                    vmid = vm.get("vmid")
                    if vm.get("status") == "running":
                        try:
                            agent_net = proxmox.nodes(node_name).qemu(vmid).agent("network-get-interfaces").get()
                            ips = []
                            for iface in agent_net.get("result", []):
                                if iface.get("name") == "lo":
                                    continue
                                for ip_info in iface.get("ip-addresses", []):
                                    if (
                                        ip_info.get("ip-address-type") == "ipv4"
                                        and ip_info.get("ip-address") != "127.0.0.1"
                                    ):
                                        ips.append(ip_info.get("ip-address"))
                            if ips:
                                guests.append({"vmid": vmid, "name": vm.get("name"), "type": "qemu", "ips": ips})
                        except Exception as e:
                            logger.debug("[ProxmoxCollector] No guest agent for VM %s on %s: %s", vmid, ip, e)
            except Exception as e:
                logger.error("[ProxmoxCollector] Error fetching VMs for %s: %s", ip, e)

            # Save facts
            if guests:
                out_path = os.path.join(facts_dir, f"proxmox_{ip}.json")
                with open(out_path, "w") as fh:
                    json.dump({"node": node_name, "guests": guests}, fh)
                logger.info("[ProxmoxCollector] Saved %d guests for %s", len(guests), ip)

        except Exception as e:
            logger.error("[ProxmoxCollector] Error collecting from %s: %s", ip, e)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    collect_proxmox_facts()
