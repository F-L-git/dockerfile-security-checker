# Рекомендации и чек-лист по безопасному написанию Dockerfile

**Версия:** 1.0  
**Дата:** Август 2026  
**Основано на:** Официальная документация Docker, CIS Docker Benchmark (раздел 4 — Container Images and Build File Configuration), OWASP Docker Security Cheat Sheet, современные практики 2025–2026 гг.

---

## 1. Введение

Dockerfile — это не просто скрипт сборки, а документ безопасности. Каждая инструкция влияет на поверхность атаки итогового образа. Цель данного документа — обобщить best practices с акцентом на:

- минимизацию привилегий;
- предотвращение внедрения уязвимостей;
- изоляцию процессов;
- минимизацию размера образа;
- исключение секретов из слоёв;
- воспроизводимость сборок.

Рекомендации применимы как для разработчиков, так и для DevOps-инженеров.

---

## 2. Ключевые принципы безопасности

| Принцип | Описание | Влияние |
|---------|----------|---------|
| Least Privilege | Процесс в контейнере работает с минимально необходимыми правами | Снижение ущерба при компрометации |
| Minimal Attack Surface | В образе только то, что нужно приложению | Меньше CVE, сложнее «жить» после эксплуатации |
| Reproducibility | Фиксация версий и digest | Защита от supply-chain атак |
| Secrets Separation | Секреты никогда не попадают в слои образа | Исключение утечек |
| Defense in Depth | Несколько независимых мер защиты | Даже при обходе одной меры остаются другие |

---

## 3. Чек-лист требований к Dockerfile

### 3.1. Базовый образ (FROM)

| № | Требование | Критичность | Обоснование / CIS |
|---|------------|-------------|-------------------|
| 1 | Использовать только доверенные базовые образы (Docker Official, Verified Publisher, Hardened Images) | Высокая | CIS 4.2 |
| 2 | Не использовать тег `:latest` | Высокая | Невоспроизводимость, риск получения скомпрометированного образа |
| 3 | Предпочтительно фиксировать digest (`@sha256:...`) | Высокая | Максимальная воспроизводимость |
| 4 | Выбирать минимальный базовый образ (alpine, distroless, scratch, slim/chiseled) | Высокая | Снижение attack surface |
| 5 | Избегать образов с полным OS (ubuntu/debian full) для production | Средняя | Большое количество ненужных пакетов |

**Рекомендация:**  
```dockerfile
# Хорошо
FROM node:22.11.0-alpine3.20@sha256:...
# Или distroless / Docker Hardened Images
FROM gcr.io/distroless/nodejs22-debian12
```

### 3.2. Пользователь и привилегии (USER)

| № | Требование | Критичность | Обоснование / CIS |
|---|------------|-------------|-------------------|
| 6 | Создавать отдельного non-root пользователя | Высокая | CIS 4.1 |
| 7 | Указывать `USER` перед `CMD`/`ENTRYPOINT` | Высокая | Процесс не должен работать от root |
| 8 | Использовать UID ≥ 1000 (предпочтительно ≥ 10000) | Средняя | Избежание пересечения с системными UID хоста |
| 9 | Устанавливать владельца файлов (`chown`) на non-root пользователя | Высокая | Принцип least privilege |
| 10 | Не запускать контейнер с `--privileged` (runtime) | Высокая | CIS 5.5 (runtime) |

**Пример:**
```dockerfile
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup
# ... копирование и установка ...
USER 10001:10001
```

### 3.3. Копирование файлов (COPY / ADD)

| № | Требование | Критичность | Обоснование / CIS |
|---|------------|-------------|-------------------|
| 11 | Использовать `COPY` вместо `ADD` | Высокая | CIS 4.9 (ADD имеет неявное поведение: распаковка, remote URL) |
| 12 | Не копировать лишнее (использовать `.dockerignore`) | Высокая | Риск попадания `.git`, `.env`, секретов, node_modules |
| 13 | Копировать только необходимые файлы/директории | Средняя | Минимизация поверхности и размера |
| 14 | Использовать `--chown` при `COPY` | Средняя | Правильные права без отдельного `RUN chown` |

### 3.4. Секреты и чувствительные данные

| № | Требование | Критичность | Обоснование / CIS |
|---|------------|-------------|-------------------|
| 15 | Никогда не хранить секреты в `ENV`, `ARG`, `LABEL`, `COPY` | Критическая | CIS 4.10 |
| 16 | Не передавать секреты через `ARG` (они остаются в истории) | Критическая | История сборки доступна |
| 17 | Для build-time секретов использовать BuildKit secrets (`--mount=type=secret`) | Высокая | Секрет не попадает в слои |
| 18 | Не писать секреты в файлы внутри образа | Критическая | Легко извлекаются |

**Правильный способ (BuildKit):**
```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci
```

### 3.5. Установка пакетов и слои

| № | Требование | Критичность | Обоснование / CIS |
|---|------------|-------------|-------------------|
| 19 | Не выполнять `apt-get update` / `apk update` отдельной командой | Высокая | CIS 4.7 |
| 20 | Объединять update + install + clean в одном `RUN` | Высокая | Кеш пакетов не остаётся в слое |
| 21 | Удалять кеш пакетного менеджера в том же слое | Высокая | Уменьшение размера и поверхности |
| 22 | Устанавливать только необходимые пакеты | Высокая | CIS 4.3 |
| 23 | Использовать `--no-cache` (apk) / `--no-install-recommends` (apt) | Средняя | Минимизация |

**Пример (Alpine):**
```dockerfile
RUN apk add --no-cache curl ca-certificates
```

**Пример (Debian/Ubuntu):**
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
```

### 3.6. Multi-stage builds

| № | Требование | Критичность | Обоснование |
|---|------------|-------------|-------------|
| 24 | Использовать multi-stage builds для разделения build и runtime | Высокая | Build-инструменты не попадают в production-образ |
| 25 | Финальный stage — минимальный (distroless / slim / scratch) | Высокая | Максимальное снижение attack surface |
| 26 | Копировать только артефакты (`COPY --from=builder`) | Высокая | Нет исходников, компиляторов, dev-зависимостей |

### 3.7. HEALTHCHECK, порты, метаданные

| № | Требование | Критичность | Обоснование / CIS |
|---|------------|-------------|-------------------|
| 27 | Добавлять `HEALTHCHECK` | Средняя | CIS 4.6 |
| 28 | Явно указывать `EXPOSE` только нужных портов | Средняя | Документирование и принцип least privilege |
| 29 | Не открывать привилегированные порты (< 1024) без необходимости | Средняя | CIS 5.8 (runtime) |
| 30 | Добавлять полезные `LABEL` (maintainer, version, description) | Низкая | Трассируемость |

### 3.8. Формат команд и ENTRYPOINT/CMD

| № | Требование | Критичность | Обоснование |
|---|------------|-------------|-------------|
| 31 | Предпочитать exec-форму (`["executable", "param"]`) | Средняя | Сигналы корректно доходят до процесса, нет shell |
| 32 | Использовать `ENTRYPOINT` для основного процесса, `CMD` — для аргументов по умолчанию | Низкая | Гибкость |
| 33 | Избегать shell-формы, если не нужен shell | Средняя | Меньше процессов, лучше обработка сигналов |

### 3.9. Дополнительные меры

| № | Требование | Критичность | Обоснование |
|---|------------|-------------|-------------|
| 34 | Удалять setuid/setgid биты с бинарников | Средняя | CIS 4.8 |
| 35 | Использовать `# syntax=docker/dockerfile:1` (или конкретную версию) | Низкая | Доступ к современным возможностям BuildKit |
| 36 | Не устанавливать SSH-сервер внутри контейнера | Высокая | CIS 5.7 |
| 37 | По возможности использовать read-only root filesystem (runtime) | Средняя | CIS 5.13 |
| 38 | Drop capabilities и `no-new-privileges` (runtime) | Высокая | CIS 5.4, 5.26 |

---

## 4. Рекомендуемая структура безопасного Dockerfile (шаблон)

```dockerfile
# syntax=docker/dockerfile:1.7

# ===== Stage 1: Build =====
FROM golang:1.23-alpine3.20 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/server ./cmd/server

# ===== Stage 2: Runtime =====
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=builder /app/server /app/server

USER nonroot:nonroot
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/server", "health"] || exit 1

ENTRYPOINT ["/app/server"]
```

---

## 5. Связь с CIS Docker Benchmark (раздел 4)

| CIS ID | Рекомендация | Реализовано в чек-листе |
|--------|--------------|-------------------------|
| 4.1 | Create a user for the container | № 6–9 |
| 4.2 | Use trusted base images | № 1–5 |
| 4.3 | Do not install unnecessary packages | № 22 |
| 4.6 | Add HEALTHCHECK | № 27 |
| 4.7 | Do not use update instructions alone | № 19–21 |
| 4.8 | Remove setuid/setgid | № 34 |
| 4.9 | Use COPY instead of ADD | № 11 |
| 4.10 | Do not store secrets in Dockerfiles | № 15–18 |

---

## 6. Как использовать этот чек-лист

1. При написании нового Dockerfile — проходить пункты по порядку.
2. При code review — использовать как критерии приёмки.
3. В CI/CD — автоматизировать проверку с помощью скрипта `dockerfile_checker.py`.
4. Для существующих образов — проводить аудит и постепенно исправлять.

---

## 7. Источники

- Docker Official Documentation — Best practices for writing Dockerfiles
- CIS Docker Benchmark (Section 4)
- OWASP Docker Security Cheat Sheet
- Docker Hardened Images documentation
- Практики 2025–2026: distroless, BuildKit secrets, pin by digest
