# Dockerfile Security Checker

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)
[![CIS inspired](https://img.shields.io/badge/CIS%20Docker-inspired-orange.svg)](https://www.cisecurity.org/benchmark/docker)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](CHANGELOG.md)

> Статический анализатор Dockerfile с фокусом на безопасность.  
> Парсит Dockerfile, проверяет соответствие best practices и CIS Docker Benchmark (раздел 4), выдаёт рекомендации и умеет исправлять простые нарушения.

---

## Возможности

| Возможность | Описание |
|-------------|----------|
| **Парсинг** | Multi-line инструкции, multi-stage builds, `# syntax=` |
| **20+ правил** | CRITICAL → INFO (секреты, root, `:latest`, ADD, пакеты…) |
| **Отчёты** | Человекочитаемый текст + JSON |
| **CI-friendly** | Exit code `0` / `1` в зависимости от CRITICAL/HIGH |
| **Автофикс** | `ADD` → `COPY`, добавление non-root `USER` |
| **Ignore** | `# check: ignore RULE-ID` в Dockerfile |
| **SARIF** | Экспорт для GitHub Code Scanning |
| **Расширяемость** | Новое правило = один метод в `SecurityChecker` |
| **Zero deps** | Только стандартная библиотека Python 3.8+ |

---

## Быстрый старт

```bash
# Клонировать
git clone https://github.com/<your-username>/dockerfile-security-checker.git
cd dockerfile-security-checker

# Проверить «плохой» Dockerfile
python3 src/dockerfile_checker.py tests/dockerfiles/bad_root_latest.Dockerfile

# Проверить «хороший» (ожидается exit 0)
python3 src/dockerfile_checker.py tests/dockerfiles/good_multistage.Dockerfile

# JSON-отчёт
python3 src/dockerfile_checker.py -f path/to/Dockerfile --json

# Автоисправление (ADD→COPY, добавление USER)
python3 src/dockerfile_checker.py Dockerfile --fix -o Dockerfile.fixed

# SARIF для GitHub Code Scanning
python3 src/dockerfile_checker.py Dockerfile --sarif report.sarif
```

### Пример вывода

```text
======================================================================
Dockerfile Security Report: tests/dockerfiles/bad_root_latest.Dockerfile
======================================================================

Сводка:
  CRITICAL: 2
  HIGH: 5
  MEDIUM: 4
  LOW: 3
  INFO: 1

----------------------------------------------------------------------
1. [CRITICAL] SECRET-001 (строка 6)
   Возможный секрет в ENV: DB_PASSWORD=supersecret123...
   → Рекомендация: Никогда не храните секреты в Dockerfile...

2. [HIGH] FROM-002 (строка 1)
   Используется тег :latest: ubuntu:latest
   → Рекомендация: Замените :latest на конкретную версию...
...
```

---

## Структура репозитория

```text
dockerfile-security-checker/
├── src/
│   └── dockerfile_checker.py          # Основной скрипт
├── docs/
│   └── Dockerfile_Security_Best_Practices_Checklist.md
├── scheme/
│   └── algorithm_scheme.md            # Алгоритмическая схема
├── tests/
│   └── dockerfiles/                   # Тестовые сценарии
│       ├── good_multistage.Dockerfile
│       ├── python_alpine_good.Dockerfile
│       ├── nodejs_partial.Dockerfile
│       ├── bad_root_latest.Dockerfile
│       └── bad_add_secrets.Dockerfile
├── .gitignore
├── LICENSE
└── README.md
```

---

## Реализованные проверки

| ID | Severity | Описание |
|----|----------|----------|
| `FROM-001` | CRITICAL | Отсутствует `FROM` |
| `FROM-002` | HIGH | Использование `:latest` / отсутствие тега |
| `FROM-003` | MEDIUM | Нет digest (`@sha256:…`) |
| `FROM-004` | MEDIUM | Потенциально недоверенный базовый образ |
| `USER-001` | HIGH | Нет `USER` (работа от root) |
| `USER-002` | HIGH | `USER` = root / 0 |
| `USER-003` | MEDIUM | UID < 1000 |
| `ADD-001` | HIGH | Используется `ADD` вместо `COPY` |
| `COPY-001` | MEDIUM | Широкое `COPY . .` |
| `SECRET-001` | CRITICAL | Секреты в `ENV` / `ARG` / `LABEL` |
| `SECRET-002` | CRITICAL | Секреты через `echo` / `printf` |
| `PKG-001` | HIGH | `update` отдельно от `install` |
| `PKG-002` | MEDIUM | Нет очистки apt lists |
| `PKG-003` | HIGH | Опасные пакеты (ssh, netcat…) |
| `HC-001` | MEDIUM | Нет `HEALTHCHECK` |
| `MS-001` | MEDIUM | Build-инструменты в single-stage |
| `CMD-001` | LOW | Shell-форма `CMD` / `ENTRYPOINT` |
| `EXPOSE-001` | LOW | Привилегированный порт < 1024 |
| `WORKDIR-001` | LOW | `WORKDIR /` |
| `SYNTAX-001` | INFO | Нет `# syntax=docker/dockerfile:…` |

Полный чек-лист с обоснованиями и ссылками на CIS — в [`docs/Dockerfile_Security_Best_Practices_Checklist.md`](docs/Dockerfile_Security_Best_Practices_Checklist.md).

---

## Алгоритм работы

```text
Dockerfile
    │
    ▼
┌──────────────────┐
│ DockerfileParser │  multi-line, multi-stage, comments
└────────┬─────────┘
         ▼
┌──────────────────┐
│ SecurityChecker  │  20+ правил (FROM, USER, secrets, packages…)
└────────┬─────────┘
         ▼
┌──────────────────┐
│ List[Finding]    │
└────────┬─────────┘
    ┌────┴────┐
    ▼         ▼
 Report    AutoFixer
Generator  (optional)
```

Подробная схема: [`scheme/algorithm_scheme.md`](scheme/algorithm_scheme.md).

---

## Расширение правил

```python
# В классе SecurityChecker добавьте метод:
def _check_my_rule(self, parsed: ParseResult):
    for instr in parsed.instructions:
        if instr.cmd == "RUN" and "bad_pattern" in instr.args.lower():
            self.findings.append(Finding(
                rule_id="MY-001",
                severity=Severity.HIGH,
                message="Описание проблемы",
                line=instr.line_number,
                recommendation="Как исправить",
            ))

# И вызовите его в check():
def check(self, parsed: ParseResult) -> List[Finding]:
    ...
    self._check_my_rule(parsed)
    return self.findings
```

---

## Тестирование

```bash
# Прогнать все тестовые Dockerfile
for f in tests/dockerfiles/*.Dockerfile; do
  echo "========== $f =========="
  python3 src/dockerfile_checker.py "$f" || true
  echo
done
```

| Файл | Ожидание |
|------|----------|
| `good_multistage.Dockerfile` | Только MEDIUM/INFO (exit 0) |
| `python_alpine_good.Dockerfile` | Только MEDIUM (exit 0) |
| `nodejs_partial.Dockerfile` | Несколько замечаний |
| `bad_root_latest.Dockerfile` | CRITICAL + HIGH |
| `bad_add_secrets.Dockerfile` | CRITICAL (секреты) + HIGH (ADD) |

---


### 8. Игнорирование правил

В Dockerfile можно отключить отдельные правила:

```dockerfile
# check: ignore FROM-003
# check: ignore SECRET-001, HC-001
```

```bash
python3 src/dockerfile_checker.py tests/dockerfiles/with_ignore.Dockerfile
# FROM-003, HC-001, COPY-001 не должны появиться в отчёте
```

### 9. SARIF-отчёт

```bash
python3 src/dockerfile_checker.py tests/dockerfiles/bad_root_latest.Dockerfile --sarif /tmp/report.sarif
# Файл совместим с GitHub Code Scanning / VS Code SARIF Viewer
```

### 10. Автофикс USER

```bash
python3 src/dockerfile_checker.py tests/dockerfiles/bad_root_latest.Dockerfile --fix -o /tmp/fixed.Dockerfile
grep -A2 -E "USER|adduser|useradd|addgroup" /tmp/fixed.Dockerfile
```

## Документация по безопасности

В репозитории есть полноценный чек-лист best practices:

- Минимальные и доверенные базовые образы
- Non-root пользователь (CIS 4.1)
- `COPY` вместо `ADD` (CIS 4.9)
- Запрет секретов в слоях (CIS 4.10)
- Multi-stage builds
- HEALTHCHECK (CIS 4.6)
- Очистка кеша пакетных менеджеров (CIS 4.7)
- Pin by digest, distroless, BuildKit secrets

→ [`docs/Dockerfile_Security_Best_Practices_Checklist.md`](docs/Dockerfile_Security_Best_Practices_Checklist.md)

---

## Источники

- [Docker Official Best Practices](https://docs.docker.com/build/building/best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) (Section 4)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- Docker Hardened Images, distroless, BuildKit secrets (практики 2025–2026)

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## Лицензия

MIT © 2026 — см. [LICENSE](LICENSE)

---

## Roadmap

### Сделано в v1.1
- [x] Игнорирование правил: `# check: ignore RULE-ID`
- [x] Автофикс: добавление non-root `USER`
- [x] Экспорт отчёта в SARIF 2.1.0

### Дальше
- [ ] Умное объединение последовательных `RUN`
- [ ] Подстановка digest базового образа (opt-in)
- [ ] Проверка `docker-compose.yml` и Kubernetes `securityContext`
- [ ] GitHub Action / pre-commit hook
- [ ] Правила для `.dockerignore`
