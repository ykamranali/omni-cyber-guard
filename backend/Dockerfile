FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl nmap unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip \
    && unzip nuclei.zip -d /usr/local/bin/ \
    && rm nuclei.zip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user and switch to it
RUN groupadd -r ocg_app && useradd -r -g ocg_app ocg_app
COPY --chown=ocg_app:ocg_app . .
USER ocg_app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
