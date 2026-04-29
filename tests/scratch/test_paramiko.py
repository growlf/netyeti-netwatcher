import paramiko
import yaml
with open("/home/netyeti/Projects/NetYeti_netwatcher/config/host_vars/192.168.88.1.yml", "r") as f:
    creds = yaml.safe_load(f)

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.88.1", username=creds['ansible_user'], password=creds['ansible_password'], look_for_keys=False, allow_agent=False)
stdin, stdout, stderr = ssh.exec_command("/ip dhcp-server lease print detail")
print(stdout.read().decode())
