FROM python:3.12.2-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ASTRA_DATABASE_URL=sqlite:////data/astra.db \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_SETTINGS_FILE=/tmp/.semgrep

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git make \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml requirements.lock security-requirements.lock README.md ./
COPY src ./src
RUN python -m pip install --timeout=120 --retries=5 -r requirements.lock \
    && python -m venv /opt/scanners \
    && /opt/scanners/bin/pip install --timeout=120 --retries=5 -r security-requirements.lock \
    && ln -s /opt/scanners/bin/semgrep /usr/local/bin/semgrep \
    && curl -fsSL -o /tmp/gitleaks.tar.gz \
       "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm -f /tmp/gitleaks.tar.gz
COPY . .

RUN useradd --create-home --uid 10001 astra \
    && mkdir -p /data \
    && chown 10001:10001 /data
USER astra
EXPOSE 8000
CMD ["uvicorn", "astra_coder.api:app", "--host", "127.0.0.1", "--port", "8000"]

FROM docker:27.5.1-cli AS docker-cli

FROM runtime AS worker
USER root
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
USER astra
CMD ["python", "-m", "astra_coder.worker_main"]

FROM runtime AS api
