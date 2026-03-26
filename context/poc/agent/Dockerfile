FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 agent && useradd -u 1000 -g agent -m agent

WORKDIR /app

COPY pyproject.toml .
COPY agent/ agent/
RUN pip install --no-cache-dir .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/certs", "/data"]

ENTRYPOINT ["/entrypoint.sh"]
