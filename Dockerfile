FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN python -c "import pydantic, pydantic_settings; from zentwhook.config import settings; assert settings is not None"
RUN chmod +x scripts/*.sh && groupadd -r -g 10001 zentwhook && useradd -r -u 10001 -g zentwhook zentwhook && mkdir -p /data && chown -R zentwhook:zentwhook /app /data
USER zentwhook
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -fsS http://127.0.0.1:8080/health || exit 1
CMD ["./scripts/start-app.sh"]
