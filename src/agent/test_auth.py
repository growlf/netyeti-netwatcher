import paramiko

try:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.88.1', username='borg', password='6*%6wS&YzlJ76gL#', look_for_keys=False, allow_agent=False)
    print("SUCCESS 192.168.88.1")
except Exception as e:
    print("FAILED 192.168.88.1:", str(e))

try:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.42.1', username='borg', password='6*%6wS&YzlJ76gL#', look_for_keys=False, allow_agent=False)
    print("SUCCESS 192.168.42.1")
except Exception as e:
    print("FAILED 192.168.42.1:", str(e))
