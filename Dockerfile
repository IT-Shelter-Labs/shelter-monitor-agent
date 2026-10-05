# Shelter Monitor: one image for both the agent (default) and the watchdog.
#   docker compose up -d                                   # agent, see docker-compose.yml
#   docker compose -f docker-compose.watchdog.yml up -d    # watchdog on another machine
ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

# systemctl / journalctl talk to the HOST's systemd and journal through the mounted
# /run/systemd and /var/log/journal (see docker-compose.yml). Nothing else is needed:
# the agent itself uses only the Python standard library.
RUN apt-get update \
    && apt-get install -y --no-install-recommends systemd \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/shelter-monitor \
    SHELTER_AGENT_CONFIG=/etc/shelter-agent/config.toml \
    SHELTER_WATCHDOG_CONFIG=/etc/shelter-watchdog/config.toml \
    SHELTER_HOST_ROOT=/host

COPY shelter_monitor /opt/shelter-monitor/shelter_monitor

# Convenience commands: docker compose exec shelter-agent shelter-agent status
RUN for c in agent watchdog; do \
        printf '#!/bin/sh\nexec python3 -m shelter_monitor %s "$@"\n' "$c" > "/usr/local/bin/shelter-$c"; \
        chmod 755 "/usr/local/bin/shelter-$c"; \
    done \
    && mkdir -p /var/lib/shelter-agent /var/lib/shelter-watchdog

HEALTHCHECK --interval=60s --timeout=10s --start-period=90s --retries=3 \
    CMD ["python3", "-m", "shelter_monitor", "agent", "healthcheck"]

ENTRYPOINT ["python3", "-m", "shelter_monitor"]
CMD ["agent", "run"]
