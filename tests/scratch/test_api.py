import routeros_api
import yaml

with open("/home/netyeti/Projects/NetYeti_netwatcher/config/host_vars/192.168.88.1.yml", "r") as f:
    creds = yaml.safe_load(f)

print("Connecting...")
try:
    connection = routeros_api.RouterOsApiPool('192.168.88.1', username=creds['ansible_user'], password=creds['ansible_password'], plaintext_login=True)
    api = connection.get_api()
    
    print("Fetching leases...")
    leases = api.get_resource('/ip/dhcp-server/lease').get()
    print(f"Got {len(leases)} leases")
    
    print("Fetching DNS cache...")
    dns = api.get_resource('/ip/dns/cache').get()
    print(f"Got {len(dns)} DNS records")
    
    connection.disconnect()
except Exception as e:
    print(f"API Error: {e}")
