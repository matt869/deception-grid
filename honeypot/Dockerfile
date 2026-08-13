# Honeypot sensor image.
#
# Runs as a non-root user on high ports. The one component that terminates
# hostile connections gets the smallest sensible surface: slim base, no build
# toolchain in the final layer, no shell tools it doesn't need.

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Only the runtime deps the sensor and pipeline actually import. paramiko and
# geoip2 are optional; add them here if you want SSH credential capture or
# geolocation inside the container.
COPY requirements.txt ./
RUN pip install --no-cache-dir \
      "SQLAlchemy>=2.0,<3.0" "PyYAML>=6.0"

# Source. Only what the sensor process needs at runtime.
COPY honeypot/ ./honeypot/
COPY pipeline/ ./pipeline/
COPY storage/ ./storage/

# Non-root. The sensor binds high ports (>=1024), so it never needs privilege.
RUN useradd --create-home --uid 10001 sensor \
    && mkdir -p /app/data \
    && chown -R sensor:sensor /app
USER sensor

# ssh, telnet, ftp, http (defaults). Map low ports to these at the host/firewall.
EXPOSE 2222 2323 2121 8081

# A liveness probe that doesn't need extra tooling: validate config loads.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -m honeypot.main --check || exit 1

ENTRYPOINT ["python", "-m", "honeypot.main"]
