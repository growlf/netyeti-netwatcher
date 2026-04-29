"""
NetWatch AI — FastAPI application entry point.

Serves the web dashboard and device management UI.  The background
collection agent is started as a daemon thread via the FastAPI lifespan hook.
"""
import ipaddress
import json
import logging
import os
import threading
import xml.etree.ElementTree as ET

import paramiko
import routeros_api
import uvicorn
import yaml
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import config
from agent import agent_loop
from parsers import parse_routeros_print  # re-exported for backwards-compat with tests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> None:
    """
    Raise HTTP 400 if *ip* is not a valid IPv4 or IPv6 address.

    This prevents path-traversal attacks where an attacker crafts a URL like
    ``/device/../../../etc/passwd`` to read arbitrary files from the host.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip!r}")


def _read_creds(ip: str) -> dict:
    """
    Load a host_vars YAML credential file for *ip*.

    Redirects to ``/`` (via RedirectResponse) when the file does not exist
    or cannot be parsed, so callers should return the result directly.
    """
    creds_file = os.path.join(config.HOST_VARS_DIR, f"{ip}.yml")
    if not os.path.exists(creds_file):
        return None
    try:
        with open(creds_file, "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _connect_proxmox(ip: str, creds: dict):
    """
    Create a ProxmoxAPI connection using the credentials stored in *creds*.

    ``verify_ssl=False`` is used when the Proxmox host does not present a
    trusted certificate (the default for self-signed lab/homelab setups).
    A warning is logged to make this explicit.
    """
    import proxmoxer
    user = creds.get('ansible_user', 'root@pam')
    password = creds.get('ansible_password', '')

    if "ansible_ssh_private_key_file" in creds:
        return proxmoxer.ProxmoxAPI(
            ip,
            user=user,
            backend='ssh_paramiko',
            private_key_file=creds['ansible_ssh_private_key_file'],
        )
    elif "!" in user:
        user_part, token_name = user.split("!")
        logger.warning(
            "[Proxmox] Connecting to %s with verify_ssl=False — "
            "certificate verification is disabled for this host.",
            ip,
        )
        return proxmoxer.ProxmoxAPI(
            ip,
            user=user_part,
            token_name=token_name,
            token_value=password,
            verify_ssl=False,
        )
    else:
        logger.warning(
            "[Proxmox] Connecting to %s with verify_ssl=False — "
            "certificate verification is disabled for this host.",
            ip,
        )
        return proxmoxer.ProxmoxAPI(ip, user=user, password=password, verify_ssl=False)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    thread = threading.Thread(target=agent_loop, daemon=True)
    thread.start()
    yield


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory=config.TEMPLATES_DIR)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    nmap_xml = os.path.join(config.FACTS_DIR, "nmap_discovery.xml")
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

                has_creds = os.path.exists(os.path.join(config.HOST_VARS_DIR, f"{ip}.yml"))

                facts = None
                interfaces = []
                facts_path = os.path.join(config.FACTS_DIR, f"{ip}_facts.json")
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
                                    'uptime': facts_data.get('ansible_net_uptime'),
                                }
                            if 'ansible_interfaces' in facts_data:
                                for iface in facts_data['ansible_interfaces']:
                                    if iface == 'lo':
                                        continue
                                    iface_data = facts_data.get(f'ansible_{iface.replace("-", "_")}', {})
                                    i_mac = iface_data.get('macaddress', 'N/A')
                                    i_ipv4 = iface_data.get('ipv4', {}).get('address', '')
                                    if i_ipv4:
                                        interfaces.append({'name': iface, 'mac': i_mac, 'ip': i_ipv4})
                    except Exception as e:
                        logger.error("Error loading facts for %s: %s", ip, e)

                devices.append({
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "is_mikrotik": is_mikrotik,
                    "is_proxmox": is_proxmox,
                    "is_dns": is_dns,
                    "has_creds": has_creds,
                    "open_ports": open_ports,
                    "facts": facts,
                    "interfaces": interfaces,
                })
        except Exception as e:
            logger.error("Error parsing nmap XML: %s", e)

    ssh_keys = []
    if os.path.exists(config.SSH_DIR):
        for f in os.listdir(config.SSH_DIR):
            if not f.endswith(".pub") and os.path.isfile(os.path.join(config.SSH_DIR, f)):
                ssh_keys.append(os.path.join(config.SSH_DIR, f))

    # Group devices into infrastructure vs endpoints
    infrastructure_networks = {}
    endpoint_devices = []

    for device in devices:
        ip_str = device.get('ip', '')
        parts = ip_str.split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "Unknown"
        is_infrastructure = (
            device.get('is_mikrotik')
            or device.get('is_proxmox')
            or device.get('is_dns')
            or device.get('has_creds')
        )
        if is_infrastructure:
            infrastructure_networks.setdefault(subnet, []).append(device)
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
            "ssh_keys": ssh_keys,
        },
    )


@app.post("/api/test_ssh", response_class=HTMLResponse)
async def test_ssh(
    ip: str = Form(...),
    auth_method: str = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    key_file: str = Form(""),
):
    _validate_ip(ip)
    try:
        ssh = paramiko.SSHClient()
        # NOTE: AutoAddPolicy silently accepts the remote host's key without
        # verification, which means this connection is NOT protected against
        # man-in-the-middle attacks.  This is acceptable for an isolated
        # homelab tool that only connects to known local devices, but should
        # be replaced with a known_hosts-based approach for production use.
        logger.warning(
            "[SSH] Connecting to %s with AutoAddPolicy — host key will not be verified.", ip
        )
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if auth_method == "password":
            if not username or not password:
                return HTMLResponse("<div class='text-red-500 mt-2 text-sm'>Username and password required.</div>")
            ssh.connect(ip, username=username, password=password, timeout=5, look_for_keys=False, allow_agent=False)

            os.makedirs(config.HOST_VARS_DIR, exist_ok=True)
            creds_file = os.path.join(config.HOST_VARS_DIR, f"{ip}.yml")
            # NOTE: Credentials are stored in plaintext YAML for Ansible
            # compatibility.  This file should be readable only by the owner
            # (mode 0600) and the directory should not be world-readable.
            with open(creds_file, "w") as f:
                os.chmod(creds_file, 0o600)
                f.write(f"ansible_user: {username}\n")
                f.write(f"ansible_password: {password}\n")
                f.write("ansible_connection: ansible.netcommon.network_cli\n")
        else:
            if not username or not key_file:
                return HTMLResponse("<div class='text-red-500 mt-2 text-sm'>Username and Key File required.</div>")
            ssh.connect(ip, username=username, key_filename=key_file, timeout=5, look_for_keys=False, allow_agent=False)

            os.makedirs(config.HOST_VARS_DIR, exist_ok=True)
            creds_file = os.path.join(config.HOST_VARS_DIR, f"{ip}.yml")
            with open(creds_file, "w") as f:
                os.chmod(creds_file, 0o600)
                f.write(f"ansible_user: {username}\n")
                f.write(f"ansible_ssh_private_key_file: {key_file}\n")
                f.write("ansible_connection: ansible.netcommon.network_cli\n")

        ssh.close()
        return HTMLResponse(f"<div class='text-green-500 font-bold mt-2 text-sm'>✓ Success! Credentials saved for {ip}.</div>")
    except HTTPException:
        raise
    except Exception as e:
        return HTMLResponse(f"<div class='text-red-500 font-bold mt-2 text-sm'>✗ Connection failed: {e}</div>")


@app.get("/proxmox/{ip}", response_class=HTMLResponse)
async def proxmox_dashboard(request: Request, ip: str):
    _validate_ip(ip)
    creds = _read_creds(ip)
    if creds is None:
        return RedirectResponse(url="/")

    error = None
    node_name = "Unknown"
    node_status = {}
    vms = []
    lxcs = []

    try:
        proxmox = _connect_proxmox(ip, creds)
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
            "error": error,
        },
    )


@app.get("/device/{ip}", response_class=HTMLResponse)
async def device_dashboard(request: Request, ip: str):
    _validate_ip(ip)
    creds = _read_creds(ip)
    if creds is None:
        return RedirectResponse(url="/")

    subnet_prefix = ".".join(ip.split(".")[:3]) + "."
    delegated_dns_servers = []
    nmap_xml = os.path.join(config.FACTS_DIR, "nmap_discovery.xml")
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
                                if (
                                    p.get('portid') == '8006'
                                    and p.find('state') is not None
                                    and p.find('state').get('state') == 'open'
                                ):
                                    is_proxmox = True
                                    break
                            url = f"/proxmox/{host_ip}" if is_proxmox else f"http://{host_ip}:5380"
                            delegated_dns_servers.append({"ip": host_ip, "is_proxmox": is_proxmox, "url": url})
        except Exception as e:
            logger.error("Error parsing delegated servers: %s", e)

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
            plaintext_login=True,
        )
        api = connection.get_api()

        try:
            dhcp_leases = api.get_resource('/ip/dhcp-server/lease').get()
        except Exception as e:
            logger.debug("[RouterOS] Could not fetch DHCP leases from %s: %s", ip, e)

        try:
            dns_cache = api.get_resource('/ip/dns/cache').get()
            dns_cache = [d for d in dns_cache if 'name' in d and 'data' in d]
        except Exception as e:
            logger.debug("[RouterOS] Could not fetch DNS cache from %s: %s", ip, e)

        try:
            interfaces = api.get_resource('/interface').get()
        except Exception as e:
            logger.debug("[RouterOS] Could not fetch interfaces from %s: %s", ip, e)

        connection.disconnect()
    except Exception as e:
        error = str(e)

    # Fallback to SSH (Paramiko) if API failed or returned empty (common for v7)
    if error or not interfaces:
        try:
            ssh = paramiko.SSHClient()
            # NOTE: Same AutoAddPolicy caveat as in test_ssh above.
            logger.warning(
                "[SSH] Connecting to %s with AutoAddPolicy — host key will not be verified.", ip
            )
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if 'ansible_ssh_private_key_file' in creds:
                ssh.connect(
                    ip,
                    username=creds.get('ansible_user', 'admin'),
                    key_filename=creds['ansible_ssh_private_key_file'],
                    look_for_keys=False,
                    allow_agent=False,
                )
            else:
                ssh.connect(
                    ip,
                    username=creds.get('ansible_user', 'admin'),
                    password=creds.get('ansible_password', ''),
                    look_for_keys=False,
                    allow_agent=False,
                )

            error = None  # Clear error since SSH connected

            _, stdout, _ = ssh.exec_command("/interface print detail")
            interfaces = parse_routeros_print(stdout.read().decode())

            _, stdout, _ = ssh.exec_command("/ip dhcp-server lease print detail")
            dhcp_leases = parse_routeros_print(stdout.read().decode())

            _, stdout, _ = ssh.exec_command("/ip dns cache print detail")
            dns_cache = parse_routeros_print(stdout.read().decode())

            ssh.close()
        except Exception as ssh_e:
            if not interfaces:
                error = f"API Error: {error} | SSH Error: {ssh_e}"

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
            "error": error,
        },
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8085)
