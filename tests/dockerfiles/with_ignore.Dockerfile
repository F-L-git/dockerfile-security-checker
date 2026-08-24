# syntax=docker/dockerfile:1
# check: ignore FROM-003, HC-001
# check: ignore COPY-001

FROM alpine:3.20

WORKDIR /app
COPY . .

# Секрет намеренно — для демонстрации, что SECRET-001 НЕ игнорируется
# ENV DEMO_TOKEN=not-a-real-secret

RUN apk add --no-cache ca-certificates

USER 10001:10001
CMD ["echo", "ok"]
