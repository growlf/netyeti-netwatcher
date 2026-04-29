import os
import time
import subprocess
import threading
import json
import yaml
import routeros_api
import kuzu_loader
import nmap_scanner
import xml.etree.ElementTree as ET
import glob
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import uvicorn
import paramiko

def update_inventory_from_nmap(inventory_path):
    nmap_xml = "./collected_facts/nmap_discovery.xml"
    if not os.path.exists(nmap_xml):
        print(f"[Agent] No nmap discovery file found at {nmap_xml}, skipping inventory update.")
        return
        
    print("[Agent] Automatically updating Ansible inventory from Nmap discovery...")
    try:
        import ipaddress
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
                    
        print(f"[Agent] Updated inventory: {len(sandbox_devices)} sandbox devices, {len(upstream_devices)} upstream devices.")
    except Exception as e:
        print(f"[Agent] Error updating inventory: {e}")

def agent_loop():
    INTERVAL = int(os.environ.get("COLLECTION_INTERVAL_SECONDS", 3600))
    print(f"[Agent Loop] Started. Interval configured for {INTERVAL} seconds.")
    
    time.sleep(5)
    
    while True:
        try:
            print("[Agent] Starting telemetry collection...")
            
            if os.environ.get("AUTO_DISCOVERY", "false").lower() == "true":
                nmap_scanner.run_scan()

            inventory_path = "/app/config/inventory.yml"
            if os.environ.get("AUTO_DISCOVERY", "false").lower() == "true":
                update_inventory_from_nmap(inventory_path)
            elif not os.path.exists(inventory_path):
                os.makedirs("/app/config", exist_ok=True)
                with open(inventory_path, "w") as f:
                    f.write("localhost ansible_connection=local\n")
            
            cmd = ["ansible-playbook", "-i", inventory_path, "get_facts.yml"]
            print(f"[Agent] Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print("[Agent] Ansible playbook encountered errors:")
                print(result.stdout)
                print(result.stderr)
            else:
                print("[Agent] Ansible telemetry collection completed.")

            print("[Agent] Starting Proxmox collection...")
            try:
                import proxmox_collector
                proxmox_collector.collect_proxmox_facts()
            except Exception as e:
                print(f"[Agent] Error running Proxmox collection: {e}")

            print("[Agent] Starting Kuzu ingestion...")
            try:
                kuzu_loader.main()
            except Exception as e:
                print(f"[Agent] Error running Kuzu loader: {e}")
                
            print("[Agent] Cycle complete.")
        except Exception as e:
            print(f"[Agent] Error during collection cycle: {e}")
        
        print(f"[Agent] Sleeping for {INTERVAL} seconds...")
        time.sleep(INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    thread = threading.Thread(target=agent_loop, daemon=True)
    thread.start()
    yield

app = FastAPI(lifespan=lifespan)
os.makedirs("/app/templates", exist_ok=True)
templates = Jinja2Templates(directory="/app/templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    nmap_xml = "/app/collected_facts/nmap_discovery.xml"
    devices = []
    
    if os.path.exists(nmap_xml):
        try:
            tree = ET.parse(nmap_xml)
            root = tree.getroot()
            for host in root.findall('host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                ip = "Unknown"
                vendor = "Unknown"
                mac = "Unknown"
                hostname = ""
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        ip = address.get('addr')
                    elif address.get('addrtype') == 'mac':
                        mac = address.get('addr')
                        vendor = address.get('vendor', 'Unknown')
                
                hostnames_tag = host.find('hostnames')
                if hostnames_tag is not None:
                    for hn in hostnames_tag.findall('hostname'):
                        if hn.get('name'):
                            hostname = hn.get('name')
                            break
                
                is_mikrotik = bool(vendor and ("Routerboard" in vendor or "MikroTik" in vendor))
                is_proxmox = False
                is_dns = False
                is_ollama = False
                services = []
                open_ports = []
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        portid = port.get('portid')
                        open_ports.append(portid)
                        if portid == '8291':
                            is_mikrotik = True
                            if vendor == "Unknown":
                                vendor = "MikroTik (Port 8291)"
                        elif portid == '8006':
                            is_proxmox = True
                            if vendor == "Unknown":
                                vendor = "Proxmox Server"
                        elif portid == '5380':
                            is_dns = True
                            if vendor == "Unknown":
                                vendor = "Technitium DNS/DHCP"
                        elif portid == '11434':
                            is_ollama = True
                            services.append({"name": "Ollama LLM Node", "port": 11434, "url": f"http://{ip}:11434"})
                            if vendor == "Unknown":
                                vendor = "Ollama AI Node"

                has_creds = os.path.exists(f"/app/config/host_vars/{ip}.yml")
                
                facts = None
                interfaces = []
                facts_path = f"/app/collected_facts/{ip}_facts.json"
                if os.path.exists(facts_path):
                    try:
                        with open(facts_path, "r") as f:
                            facts_data = json.load(f)
                            if 'ansible_net_model' in facts_data:
                                facts = {
                                    'model': facts_data.get('ansible_net_model'),
                                    'version': facts_data.get('ansible_net_version'),
                                    'cpu_load': facts_data.get('ansible_net_cpu_load'),
                                    'memfree_mb': facts_data.get('ansible_net_memfree_mb'),
                                    'uptime': facts_data.get('ansible_net_uptime')
                                }
                            if 'ansible_interfaces' in facts_data:
                                for iface in facts_data['ansible_interfaces']:
                                    if iface == 'lo':
                                        continue
                                    iface_data = facts_data.get(f'ansible_{iface.replace("-", "_")}', {})
                                    i_mac = iface_data.get('macaddress', 'N/A')
                                    i_ipv4 = iface_data.get('ipv4', {}).get('address', '')
                                    if i_ipv4:
                                        interfaces.append({
                                            'name': iface,
                                            'mac': i_mac,
                                            'ip': i_ipv4
                                        })
                    except Exception as e:
                        print(f"Error loading facts for {ip}: {e}")
                
                devices.append({
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "is_mikrotik": is_mikrotik,
                    "is_proxmox": is_proxmox,
                    "is_dns": is_dns,
                    "is_ollama": is_ollama,
                    "has_creds": has_creds,
                    "open_ports": open_ports,
                    "services": services,
                    "facts": facts,
                    "interfaces": interfaces
                })
        except Exception as e:
            print(f"Error parsing xml: {e}")
            
    ssh_keys = []
    if os.path.exists("/root/.ssh"):
        for f in os.listdir("/root/.ssh"):
            if not f.endswith(".pub") and os.path.isfile(os.path.join("/root/.ssh", f)):
                ssh_keys.append(f"/root/.ssh/{f}")
                
    # Group devices
    infrastructure_networks = {}
    endpoint_devices = []
    
    for device in devices:
        # Determine subnet
        ip_str = device.get('ip', '')
        parts = ip_str.split('.')
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        else:
            subnet = "Unknown"
            
        is_infrastructure = device.get('is_mikrotik') or device.get('is_proxmox') or device.get('is_dns') or device.get('has_creds')
        
        if is_infrastructure:
            if subnet not in infrastructure_networks:
                infrastructure_networks[subnet] = []
            infrastructure_networks[subnet].append(device)
        else:
            endpoint_devices.append(device)
                
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html", 
        context={
            "request": request, 
            "devices": devices,
            "infrastructure_networks": infrastructure_networks,
            "endpoint_devices": endpoint_devices,
            "ssh_keys": ssh_keys
        }
    )

@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    # Parse available ollamas
    nmap_xml = "/app/collected_facts/nmap_discovery.xml"
    detected_ollamas = []
    
    if os.path.exists(nmap_xml):
        try:
            tree = ET.parse(nmap_xml)
            for host in tree.getroot().findall('host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                ip = ""
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        ip = address.get('addr')
                
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and port.get('portid') == '11434' and state.get('state') == 'open':
                        detected_ollamas.append(ip)
                        break
        except Exception:
            pass
            
    # Load current settings
    settings = {}
    settings_path = "/app/config/settings.json"
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r") as f:
                settings = json.load(f)
        except Exception:
            pass
            
    return templates.TemplateResponse(
        request=request,
        name="config.html", 
        context={
            "request": request, 
            "detected_ollamas": detected_ollamas,
            "settings": settings
        }
    )

@app.post("/api/config/llm", response_class=HTMLResponse)
async def save_llm_config(ollama_url: str = Form(""), ollama_model: str = Form("")):
    settings_path = "/app/config/settings.json"
    settings = {}
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r") as f:
                settings = json.load(f)
        except Exception:
            pass
            
    settings["ollama_url"] = ollama_url
    settings["ollama_model"] = ollama_model
    
    os.makedirs("/app/config", exist_ok=True)
    with open(settings_path, "w") as f:
        json.dump(settings, f)
        
    return HTMLResponse("<div class='text-green-500 font-bold mt-2 text-sm'>✓ LLM Settings saved successfully.</div>")

@app.post("/api/test_ssh", response_class=HTMLResponse)
async def test_ssh(ip: str = Form(...), auth_method: str = Form(...), username: str = Form(""), password: str = Form(""), key_file: str = Form("")):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if auth_method == "password":
            if not username or not password:
                return HTMLResponse("<div class='text-red-500 mt-2 text-sm'>Username and password required.</div>")
            ssh.connect(ip, username=username, password=password, timeout=5, look_for_keys=False, allow_agent=False)
            
            os.makedirs("/app/config/host_vars", exist_ok=True)
            with open(f"/app/config/host_vars/{ip}.yml", "w") as f:
                f.write(f"ansible_user: {username}\n")
                f.write(f"ansible_password: {password}\n")
                f.write("ansible_connection: ansible.netcommon.network_cli\n")
                
        else:
            if not username or not key_file:
                return HTMLResponse("<div class='text-red-500 mt-2 text-sm'>Username and Key File required.</div>")
            ssh.connect(ip, username=username, key_filename=key_file, timeout=5, look_for_keys=False, allow_agent=False)
            
            os.makedirs("/app/config/host_vars", exist_ok=True)
            with open(f"/app/config/host_vars/{ip}.yml", "w") as f:
                f.write(f"ansible_user: {username}\n")
                f.write(f"ansible_ssh_private_key_file: {key_file}\n")
                f.write("ansible_connection: ansible.netcommon.network_cli\n")
                
        ssh.close()
        return HTMLResponse(f"<div class='text-green-500 font-bold mt-2 text-sm'>✓ Success! Credentials saved for {ip}.</div>")
    except Exception as e:
        return HTMLResponse(f"<div class='text-red-500 font-bold mt-2 text-sm'>✗ Connection failed: {str(e)}</div>")

@app.get("/proxmox/{ip}", response_class=HTMLResponse)
async def proxmox_dashboard(request: Request, ip: str):
    import proxmoxer
    creds_file = f"/app/config/host_vars/{ip}.yml"
    if not os.path.exists(creds_file):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/")
        
    try:
        with open(creds_file, "r") as f:
            creds = yaml.safe_load(f)
    except Exception:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/")
        
    error = None
    node_name = "Unknown"
    node_status = {}
    vms = []
    lxcs = []
    
    try:
        user = creds.get('ansible_user', 'root@pam')
        password = creds.get('ansible_password', '')
        
        if "ansible_ssh_private_key_file" in creds:
            proxmox = proxmoxer.ProxmoxAPI(
                ip, 
                user=user, 
                backend='ssh_paramiko',
                private_key_file=creds['ansible_ssh_private_key_file']
            )
        elif "!" in user:
            # Token authentication
            user_part, token_name = user.split("!")
            proxmox = proxmoxer.ProxmoxAPI(
                ip, 
                user=user_part, 
                token_name=token_name,
                token_value=password, 
                verify_ssl=False
            )
        else:
            # Password authentication
            proxmox = proxmoxer.ProxmoxAPI(
                ip, 
                user=user, 
                password=password, 
                verify_ssl=False
            )
            
        nodes = proxmox.nodes.get()
        if nodes:
            node_name = nodes[0]['node']
            node_status = proxmox.nodes(node_name).status.get()
            vms = proxmox.nodes(node_name).qemu.get()
            lxcs = proxmox.nodes(node_name).lxc.get()
            
    except Exception as e:
        error = str(e)
        
    return templates.TemplateResponse(
        request=request,
        name="proxmox.html", 
        context={
            "request": request, 
            "ip": ip,
            "node_name": node_name,
            "node_status": node_status,
            "vms": vms,
            "lxcs": lxcs,
            "error": error
        }
    )

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

@app.get("/device/{ip}", response_class=HTMLResponse)
async def device_dashboard(request: Request, ip: str):
    creds_file = f"/app/config/host_vars/{ip}.yml"
    if not os.path.exists(creds_file):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/")
        
    try:
        with open(creds_file, "r") as f:
            creds = yaml.safe_load(f)
    except Exception:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/")
        
    subnet_prefix = ".".join(ip.split(".")[:3]) + "."
    delegated_dns_servers = []
    nmap_xml = "/app/collected_facts/nmap_discovery.xml"
    if os.path.exists(nmap_xml):
        try:
            tree = ET.parse(nmap_xml)
            for host in tree.getroot().findall('host'):
                host_ip = ""
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        host_ip = address.get('addr')
                if host_ip.startswith(subnet_prefix) and host_ip != ip:
                    for port in host.findall('.//port'):
                        state = port.find('state')
                        if state is not None and port.get('portid') == '5380' and state.get('state') == 'open':
                            is_proxmox = False
                            for p in host.findall('.//port'):
                                if p.get('portid') == '8006' and p.find('state') is not None and p.find('state').get('state') == 'open':
                                    is_proxmox = True
                                    break
                            
                            url = f"/proxmox/{host_ip}" if is_proxmox else f"http://{host_ip}:5380"
                            delegated_dns_servers.append({
                                "ip": host_ip,
                                "is_proxmox": is_proxmox,
                                "url": url
                            })
        except Exception as e:
            print(f"Error parsing delegated servers: {e}")

    dhcp_leases = []
    dns_cache = []
    interfaces = []
    error = None
    
    # Try RouterOS API first (works well for v6)
    try:
        connection = routeros_api.RouterOsApiPool(
            ip, 
            username=creds.get('ansible_user', 'admin'), 
            password=creds.get('ansible_password', ''), 
            plaintext_login=True
        )
        api = connection.get_api()
        
        try:
            dhcp_leases = api.get_resource('/ip/dhcp-server/lease').get()
        except Exception:
            pass
            
        try:
            dns_cache = api.get_resource('/ip/dns/cache').get()
            dns_cache = [d for d in dns_cache if 'name' in d and 'data' in d]
        except Exception:
            pass
            
        try:
            interfaces = api.get_resource('/interface').get()
        except Exception:
            pass
            
        connection.disconnect()
    except Exception as e:
        error = str(e)
        
    # Fallback to SSH (Paramiko) if API failed or returned empty (common for v7)
    if error or not interfaces:
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using key if available, else password
            if 'ansible_ssh_private_key_file' in creds:
                ssh.connect(ip, username=creds.get('ansible_user', 'admin'), key_filename=creds['ansible_ssh_private_key_file'], look_for_keys=False, allow_agent=False)
            else:
                ssh.connect(ip, username=creds.get('ansible_user', 'admin'), password=creds.get('ansible_password', ''), look_for_keys=False, allow_agent=False)
            
            error = None # Clear error since SSH connected
            
            # Fetch Interfaces
            _, stdout, _ = ssh.exec_command("/interface print detail")
            interfaces = parse_routeros_print(stdout.read().decode())
            
            # Fetch DHCP
            _, stdout, _ = ssh.exec_command("/ip dhcp-server lease print detail")
            dhcp_leases = parse_routeros_print(stdout.read().decode())
            
            # Fetch DNS Cache
            _, stdout, _ = ssh.exec_command("/ip dns cache print detail")
            dns_cache = parse_routeros_print(stdout.read().decode())
            
            ssh.close()
        except Exception as ssh_e:
            if not interfaces:
                error = f"API Error: {error} | SSH Error: {str(ssh_e)}"
        
    return templates.TemplateResponse(
        request=request,
        name="device.html", 
        context={
            "request": request, 
            "ip": ip,
            "dhcp_leases": dhcp_leases,
            "dns_cache": dns_cache,
            "delegated_dns_servers": delegated_dns_servers,
            "interfaces": interfaces,
            "error": error
        }
    )

@app.get("/services/{ip}", response_class=HTMLResponse)
async def services_dashboard(request: Request, ip: str):
    # Parse available services for this ip from Nmap
    nmap_xml = "/app/collected_facts/nmap_discovery.xml"
    services = []
    
    if os.path.exists(nmap_xml):
        try:
            tree = ET.parse(nmap_xml)
            for host in tree.getroot().findall('host'):
                host_ip = ""
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        host_ip = address.get('addr')
                
                if host_ip == ip:
                    for port in host.findall('.//port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            portid = port.get('portid')
                            if portid == '11434':
                                services.append({"name": "Ollama LLM Node", "port": 11434, "url": f"http://{ip}:11434"})
                            elif portid == '80':
                                services.append({"name": "HTTP Web Interface", "port": 80, "url": f"http://{ip}"})
                            elif portid == '443':
                                services.append({"name": "HTTPS Web Interface", "port": 443, "url": f"https://{ip}"})
                            elif portid == '5380':
                                services.append({"name": "Technitium DNS Panel", "port": 5380, "url": f"http://{ip}:5380"})
                            elif portid == '8006':
                                services.append({"name": "Proxmox Web UI", "port": 8006, "url": f"https://{ip}:8006"})
                    break
        except Exception:
            pass

    return templates.TemplateResponse(
        request=request,
        name="services.html", 
        context={
            "request": request, 
            "ip": ip,
            "services": services
        }
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8085)
