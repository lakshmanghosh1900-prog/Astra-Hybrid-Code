FROM python:3.12.2-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml requirements.lock README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.lock
COPY . .

RUN useradd --create-home --uid 10001 astra
USER astra
EXPOSE 8000
CMD ["uvicorn", "astra_coder.api:app", "--host", "127.0.0.1", "--port", "8000"]
