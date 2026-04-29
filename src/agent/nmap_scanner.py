import subprocess
import ipaddress
import os
import json

def get_local_subnet():
    try:
        # Find default route interface
        route_out = subprocess.check_output("ip route | grep default", shell=True, text=True)
        if not route_out:
            return None
        parts = route_out.strip().split()
        if 'dev' in parts:
            iface = parts[parts.index('dev') + 1]
        else:
            return None
            
        if 'via' in parts:
            gateway_ip = parts[parts.index('via') + 1]
            os.makedirs("/app/collected_facts", exist_ok=True)
            with open("/app/collected_facts/gateway.txt", "w") as f:
                f.write(gateway_ip)
        
        # Get CIDR for that interface
        addr_out = subprocess.check_output(f"ip -o -f inet addr show {iface}", shell=True, text=True)
        cidr = addr_out.strip().split()[3]
        
        # Convert to network address (e.g. 192.168.1.10/24 -> 192.168.1.0/24)
        net = ipaddress.IPv4Interface(cidr).network
        return str(net)
    except Exception as e:
        print(f"[Nmap] Error finding local subnet: {e}")
        return None

def run_traceroute():
    target = os.environ.get("TRACEROUTE_TARGET", "8.8.8.8")
    wan_ip_override = os.environ.get("ROUTER_WAN_IP", "").strip()
    print(f"[Nmap] Running traceroute to {target} to discover upstream networks...")
    
    cmd = ["traceroute", "-n", "-m", "10", "-w", "2", "-q", "1", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    hops = []
    subnets = []
    wan_ip = wan_ip_override if wan_ip_override else None
    
    for line in result.stdout.split('\n')[1:]:
        parts = line.strip().split()
        if len(parts) >= 2:
            ip = parts[1]
            if ip == "*":
                continue
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if ip_obj.is_private:
                    hops.append(ip)
                    # Assume /24 for upstream networks
                    net = str(ipaddress.IPv4Interface(f"{ip}/24").network)
                    if net not in subnets:
                        subnets.append(net)
                else:
                    if not wan_ip:
                        wan_ip = ip
                    hops.append(wan_ip)
                    break # Stop at first public IP
            except ValueError:
                pass
                
    os.makedirs("/app/collected_facts", exist_ok=True)
    with open("/app/collected_facts/traceroute.json", "w") as f:
        json.dump({"hops": hops, "wan_ip": wan_ip}, f)
        
    print(f"[Nmap] Traceroute found upstream hops: {hops}")
    print(f"[Nmap] Discovered upstream subnets: {subnets}")
    if wan_ip:
        print(f"[Nmap] WAN IP identified as: {wan_ip}")
        
    return subnets

def run_scan():
    print("[Nmap] Starting automatic local network discovery...")
    subnet = get_local_subnet()
    
    extra_subnets = run_traceroute()
    all_subnets = []
    if subnet:
        all_subnets.append(subnet)
    for s in extra_subnets:
        if s not in all_subnets:
            all_subnets.append(s)
            
    if not all_subnets:
        print("[Nmap] Could not determine any subnets to scan. Skipping auto-discovery.")
        return
        
    # Ensure we scan localhost to catch services bound only to loopback (like default Ollama)
    if "127.0.0.1" not in all_subnets:
        all_subnets.append("127.0.0.1")
    
    print(f"[Nmap] Scanning subnets: {all_subnets}. Checking for open ports 22, 80, 443, 5380, 8006, 8291, 11434...")
    output_file = "/app/collected_facts/nmap_discovery.xml"
    
    cmd = ["nmap", "-p", "22,80,443,5380,8006,8291,11434"] + all_subnets + ["-oX", output_file]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"[Nmap] Discovery complete. Results saved to {output_file}")
    else:
        print(f"[Nmap] Scan failed: {result.stderr}")

if __name__ == "__main__":
    run_scan()
