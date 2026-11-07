FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	PYTHONPATH=/app

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY --chown=appuser:appuser cmd/ ./cmd/
COPY --chown=appuser:appuser internal/ ./internal/

USER appuser

ENTRYPOINT ["python", "cmd/umasign/main.py"]
