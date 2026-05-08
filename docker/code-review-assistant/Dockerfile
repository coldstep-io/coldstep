# Expert code-review MCP assistant (slim). Stdio MCP; no external APIs or API keys.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="coldstep-code-review-mcp" \
      org.opencontainers.image.description="Stdio MCP code-review rubric (no external APIs)" \
      org.opencontainers.image.source="https://github.com/coldstep-io/coldstep"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY server.py .
COPY prompts ./prompts

RUN chown -R appuser:appuser /app

USER appuser

# Optional: mount read-only corpora (RFC mirrors, kernel docs) at /data/docs
VOLUME ["/data/docs"]

ENTRYPOINT ["python", "/app/server.py"]
