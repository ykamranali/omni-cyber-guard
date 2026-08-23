FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl nmap unzip lynis \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip \
    && unzip nuclei.zip -d /usr/local/bin/ \
    && rm nuclei.zip

# nmap needs raw sockets for SYN scanning and OS detection. The worker
# container is granted CAP_NET_RAW, but container capabilities land in root's
# set — this image runs as the non-root user ocg_app, which inherits none of
# them. Without the file capability below, every nmap run silently degrades to
# an unprivileged TCP connect scan (no SYN, no OS detection, no MAC address),
# or fails outright, and the scan reports a thinner result as though that were
# what the network showed.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user and switch to it
RUN groupadd -r ocg_app && useradd -r -m -g ocg_app ocg_app
COPY --chown=ocg_app:ocg_app . .
USER ocg_app

# Download nuclei templates so the engine is fully available
RUN nuclei -update-templates

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
