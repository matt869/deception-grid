# API image. Serves the read API over the shared database.

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# psycopg2-binary is the PostgreSQL driver SQLAlchemy needs for the
# docker-compose default DATABASE_URL (postgresql://); unused under SQLite.
# geoip2 powers the on-demand /api/stats/enrich lookup when a GeoLite2 db is
# mounted (the sensor does the inline enrichment for stored events).
COPY requirements.txt ./
RUN pip install --no-cache-dir \
      "SQLAlchemy>=2.0,<3.0" "PyYAML>=6.0" "psycopg2-binary>=2.9" "geoip2>=4.8" \
      "fastapi>=0.110,<1.0" "uvicorn[standard]>=0.29" \
      "pydantic>=2.6,<3.0" "python-multipart>=0.0.9"

COPY api/ ./api/
COPY pipeline/ ./pipeline/
COPY storage/ ./storage/

RUN useradd --create-home --uid 10002 apiuser \
    && mkdir -p /app/data \
    && chown -R apiuser:apiuser /app
USER apiuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=8s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)" \
        || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
