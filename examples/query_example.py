import kuzu
import urllib.request
import json
import urllib.parse

def query_kuzu_discovery():
    """
    Query the Kuzu Graph Database for all hosts discovered on the LAN
    by the Nmap auto-discovery agent.
    """
    print("\n--- KUZU GRAPH DB: Local LAN Discovery ---")
    try:
        # Connect to the local data volume directly
        db = kuzu.Database('./kuzu-data/netwatch.kuzu')
        conn = kuzu.Connection(db)
        
        # Cypher query to get Hosts and their network interfaces
        query = """
        MATCH (h:Host)-[:HAS_INTERFACE]->(i:Interface)
        RETURN h.hostname, h.ip, i.mac_address, i.name as vendor
        """
        results = conn.execute(query)
        
        print(f"{'Hostname':<25} | {'IP Address':<15} | {'MAC Address':<17} | {'Vendor'}")
        print("-" * 80)
        
        count = 0
        while results.has_next():
            row = results.get_next()
            print(f"{str(row[0]):<25} | {str(row[1]):<15} | {str(row[2]):<17} | {str(row[3])}")
            count += 1
            
        if count == 0:
            print("No hosts found. The agent may still be running its first discovery scan.")
            
    except Exception as e:
        print(f"Error querying Kuzu: {e}")
        print("Note: If Kuzu throws a lock error, ensure the agent container isn't actively writing.")


def query_victoria_metrics():
    """
    Query VictoriaMetrics via its PromQL HTTP API to see what local metrics
    are actively being scraped.
    """
    print("\n--- VICTORIA METRICS: Active Time-Series Targets ---")
    
    # Query the 'up' metric, which returns 1 for targets that are successfully being scraped
    query = "up"
    encoded_query = urllib.parse.quote(query)
    url = f"http://localhost:8428/api/v1/query?query={encoded_query}"
    
    try:
        req = urllib.request.urlopen(url)
        res = json.loads(req.read())
        
        if res.get('status') == 'success':
            results = res['data']['result']
            if not results:
                print("No active metrics targets found. (Check your config/prometheus.yml for scrape targets!)")
            
            for item in results:
                metric = item['metric']
                val = item['value'][1] # Value is [timestamp, "value"]
                instance = metric.get('instance', 'Unknown')
                job = metric.get('job', 'Unknown')
                print(f"Target: {instance:<20} | Job: {job:<25} | Status (up): {val}")
        else:
            print(f"VictoriaMetrics returned an error: {res}")
            
    except Exception as e:
        print(f"Error querying VictoriaMetrics: {e}")
        print("Note: Make sure your docker compose stack is running!")

if __name__ == "__main__":
    print("Fetching network intelligence...")
    query_kuzu_discovery()
    query_victoria_metrics()
    print("\nDone.")
