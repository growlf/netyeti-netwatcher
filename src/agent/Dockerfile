FROM python:3.10.14-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sshpass openssh-client nmap iproute2 traceroute && \
    rm -rf /var/lib/apt/lists/*

COPY src/agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN ansible-galaxy collection install community.routeros

COPY src/agent/ .

ENV PYTHONPATH=/app

# Ensure runtime directories exist for volume mounts
RUN mkdir -p /app/config /app/collected_facts /app/templates

CMD ["python3", "main.py"]
