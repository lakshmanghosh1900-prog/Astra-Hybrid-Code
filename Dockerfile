FROM python:3.12.2-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ASTRA_DATABASE_URL=sqlite:////data/astra.db

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git make \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml requirements.lock README.md ./
COPY src ./src
RUN python -m pip install --timeout=120 --retries=5 -r requirements.lock
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
