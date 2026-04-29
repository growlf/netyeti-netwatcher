import librouteros
import yaml
with open("/home/netyeti/Projects/NetYeti_netwatcher/config/host_vars/192.168.42.1.yml", "r") as f:
    creds = yaml.safe_load(f)
api = librouteros.connect("192.168.42.1", username=creds.get("ansible_user"), password=creds.get("ansible_password"))
print(len(list(api.path('interface'))))
