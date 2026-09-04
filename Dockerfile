FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LIFEDB_VAULT=/data \
    LIFEDB_SERVER_BIND=0.0.0.0 \
    LIFEDB_PORT=7331 \
    LIFEDB_INGEST_SENSITIVITY_FLOOR=personal

WORKDIR /app
COPY pyproject.toml README.md SPEC.md ./
COPY src ./src
COPY schemas ./schemas
COPY docs ./docs

RUN pip install --no-cache-dir . \
    && addgroup --system --gid 10001 lifedb \
    && adduser --system --uid 10001 --ingroup lifedb --home /nonexistent --no-create-home lifedb

USER lifedb
EXPOSE 7331

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7331/health', timeout=2).read()"

ENTRYPOINT ["lifedb"]
CMD ["serve"]
