import os
import json
import yaml
import proxmoxer

def collect_proxmox_facts():
    print("[ProxmoxCollector] Starting Proxmox data collection...")
    config_dir = "/app/config/host_vars"
    facts_dir = "/app/collected_facts"
    os.makedirs(facts_dir, exist_ok=True)
    
    if not os.path.exists(config_dir):
        print("[ProxmoxCollector] No config directory found.")
        return

    for f in os.listdir(config_dir):
        if not f.endswith(".yml"):
            continue
            
        ip = f.replace(".yml", "")
        filepath = os.path.join(config_dir, f)
        
        try:
            with open(filepath, "r") as cf:
                creds = yaml.safe_load(cf)
        except Exception:
            continue
            
        user = creds.get('ansible_user', '')
        password = creds.get('ansible_password', '')
        
        # Determine if it's Proxmox by seeing if username has realm or token
        if "!" in user or "@pam" in user or "@pve" in user:
            print(f"[ProxmoxCollector] Connecting to Proxmox at {ip}...")
            try:
                if "ansible_ssh_private_key_file" in creds:
                    proxmox = proxmoxer.ProxmoxAPI(
                        ip, 
                        user=user, 
                        backend='ssh_paramiko',
                        private_key_file=creds['ansible_ssh_private_key_file']
                    )
                elif "!" in user:
                    user_part, token_name = user.split("!")
                    proxmox = proxmoxer.ProxmoxAPI(
                        ip, 
                        user=user_part, 
                        token_name=token_name,
                        token_value=password, 
                        verify_ssl=False
                    )
                else:
                    proxmox = proxmoxer.ProxmoxAPI(
                        ip, 
                        user=user, 
                        password=password, 
                        verify_ssl=False
                    )
                
                nodes = proxmox.nodes.get()
                if not nodes:
                    continue
                    
                node_name = nodes[0]['node']
                
                # Collect VMs and LXCs with IP addresses
                guests = []
                
                # LXC
                try:
                    lxcs = proxmox.nodes(node_name).lxc.get()
                    for lxc in lxcs:
                        vmid = lxc.get("vmid")
                        config = proxmox.nodes(node_name).lxc(vmid).config.get()
                        # Extract IP from net0, net1, etc.
                        ips = []
                        for k, v in config.items():
                            if k.startswith("net") and "ip=" in v:
                                # v could be: name=eth0,bridge=vmbr0,firewall=1,gw=192.168.1.1,hwaddr=...,ip=192.168.1.100/24,type=veth
                                parts = v.split(",")
                                for p in parts:
                                    if p.startswith("ip="):
                                        ip_val = p.split("=")[1].split("/")[0]
                                        if ip_val and ip_val != "dhcp":
                                            ips.append(ip_val)
                        if ips:
                            guests.append({
                                "vmid": vmid,
                                "name": lxc.get("name"),
                                "type": "lxc",
                                "ips": ips
                            })
                except Exception as e:
                    print(f"[ProxmoxCollector] Error fetching LXCs for {ip}: {e}")
                
                # QEMU (VMs)
                try:
                    vms = proxmox.nodes(node_name).qemu.get()
                    for vm in vms:
                        vmid = vm.get("vmid")
                        # IP addresses for VMs are harder without guest agent, but we can try agent
                        if vm.get("status") == "running":
                            try:
                                agent_net = proxmox.nodes(node_name).qemu(vmid).agent("network-get-interfaces").get()
                                ips = []
                                for iface in agent_net.get("result", []):
                                    if iface.get("name") == "lo": continue
                                    for ip_info in iface.get("ip-addresses", []):
                                        if ip_info.get("ip-address-type") == "ipv4" and ip_info.get("ip-address") != "127.0.0.1":
                                            ips.append(ip_info.get("ip-address"))
                                if ips:
                                    guests.append({
                                        "vmid": vmid,
                                        "name": vm.get("name"),
                                        "type": "qemu",
                                        "ips": ips
                                    })
                            except Exception:
                                pass # No guest agent
                except Exception as e:
                    print(f"[ProxmoxCollector] Error fetching VMs for {ip}: {e}")
                
                # Save facts
                if guests:
                    out_path = os.path.join(facts_dir, f"proxmox_{ip}.json")
                    with open(out_path, "w") as f:
                        json.dump({"node": node_name, "guests": guests}, f)
                    print(f"[ProxmoxCollector] Saved {len(guests)} guests for {ip}")
                
            except Exception as e:
                print(f"[ProxmoxCollector] Error collecting from {ip}: {e}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    collect_proxmox_facts()
