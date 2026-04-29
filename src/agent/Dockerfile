FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sshpass openssh-client nmap iproute2 traceroute && \
    rm -rf /var/lib/apt/lists/*

COPY src/agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN ansible-galaxy collection install community.routeros

COPY src/agent/ .
COPY tests/ /tests/

ENV PYTHONPATH=/app
RUN pytest /tests/unit/

# Ensure config directory exists for mounting
RUN mkdir -p /app/config /app/collected_facts

CMD ["python3", "main.py"]
