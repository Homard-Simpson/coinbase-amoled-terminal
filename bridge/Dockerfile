# syntax=docker/dockerfile:1.7
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 bridge \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin bridge

COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && rm -rf /root/.cache

RUN install -d -o bridge -g bridge -m 0700 /data
USER 10001:10001

VOLUME ["/data"]
EXPOSE 8788

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8788/healthz', timeout=2).read()"]

ENTRYPOINT ["coinbase-amoled-bridge", "--data-dir", "/data"]
# Plain HTTP is intended only inside a private container network or behind a
# trusted TLS reverse proxy. Bind the published host port to loopback by default.
CMD ["serve", "--host", "0.0.0.0", "--port", "8788", "--allow-insecure-public-bind"]
