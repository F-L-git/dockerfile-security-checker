# syntax=docker/dockerfile:1

FROM python:3.12.7-alpine3.20 AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12.7-alpine3.20

RUN addgroup -g 10001 -S app && \
    adduser -u 10001 -S app -G app

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=app:app app/ ./

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
