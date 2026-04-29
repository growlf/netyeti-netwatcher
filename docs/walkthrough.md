# Automatic Local Network Discovery Implementation

The agent has been successfully upgraded to perform automatic local network discovery using `nmap`. Here is a walkthrough of what was accomplished:

## 1. Network Visibility (`docker-compose.yml`)
The `netwatch_agent` container is now configured with `network_mode: host` and the environment variable `AUTO_DISCOVERY=true`. This enables the container to see the actual host's network interfaces, routing tables, and perform ARP requests (which are critical for retrieving device MAC addresses on the local subnet).

## 2. Nmap Discovery Script (`src/agent/nmap_scanner.py`)
A new script has been created which:
- Uses `ip route` (via `iproute2` which was added to the `Dockerfile`) to dynamically identify the default gateway and determine the local CIDR subnet (e.g. `192.168.1.0/24`).
- Executes a fast `nmap -sn` ping sweep across the determined subnet.
- Exports the scan results in XML format to `/app/collected_facts/nmap_discovery.xml`.

## 3. Kuzu Graph Ingestion (`src/agent/kuzu_loader.py`)
The Kuzu DB loader was updated with a new function (`load_nmap_facts`) that parses the `nmap_discovery.xml` file. It extracts the IP address, MAC address, and hardware vendor of every active host on the network. 
- It creates/updates a `Host` node using the MAC address as a unique identifier (preventing duplicates if IP addresses change).
- It creates an `Interface` node for the device, and sets up a `HAS_INTERFACE` relationship in the graph.

## 4. Main Agent Loop (`src/agent/main.py`)
The main collection loop now checks for the `AUTO_DISCOVERY` environment variable. If true, it runs the `nmap_scanner.py` script first, before falling back to the standard Ansible fact collection. Both datasets are then ingested into the Kuzu DB seamlessly!

> [!NOTE]
> The next time you run `docker compose up -d --build`, the agent will automatically discover all active devices on your LAN and map them into the graph database without any manual inventory configuration!
