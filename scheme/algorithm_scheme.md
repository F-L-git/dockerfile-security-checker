# Алгоритмическая схема работы приложения Dockerfile Security Checker

## 1. Общая схема (высокий уровень)

```
┌─────────────────┐
│  Входной файл   │
│   Dockerfile    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  DockerfileParser│
│  - чтение файла │
│  - разбор строк │
│  - multi-line   │
│  - multi-stage  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ParseResult     │
│ (instructions,  │
│  stages, raw)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ SecurityChecker │
│  Правила:       │
│  FROM / USER /  │
│  COPY-ADD /     │
│  SECRETS / PKG /│
│  HEALTHCHECK /  │
│  MULTI-STAGE /  │
│  CMD / EXPOSE   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ List[Finding]   │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────────┐
│ Report │ │ AutoFixer  │
│Generator│ │ (опционально)│
└────────┘ └────────────┘
    │              │
    ▼              ▼
 Отчёт в        Исправленный
 консоль/JSON    Dockerfile
```

## 2. Детальный алгоритм парсинга

```
Функция parse(content: str) → ParseResult
  lines ← content.splitlines()
  i ← 0
  Пока i < len(lines):
    line ← lines[i]
    Если строка пустая или комментарий (кроме # syntax=):
      Если # syntax= → has_syntax_directive = True
      i++
      continue
    # Сборка multi-line (окончание на \)
    full_line ← line
    line_num ← i + 1
    Пока full_line заканчивается на '\' и есть следующая строка:
      i++
      full_line ← full_line без '\' + ' ' + lines[i]
    match ← регулярка инструкции
    Если match:
      cmd ← UPPER(group1)
      args ← group2
      Добавить Instruction(cmd, args, full_line, line_num)
      Если cmd == "FROM":
        Извлечь имя stage (AS name) или сгенерировать
    i++
  Вернуть ParseResult
```

## 3. Алгоритм проверки (SecurityChecker.check)

```
Для каждого правила:
  1. FROM-001..004
     - Есть ли FROM?
     - Есть ли :latest или отсутствие тега?
     - Есть ли @sha256: digest?
     - Доверенный ли базовый образ (эвристика по префиксу)?

  2. USER-001..003
     - Есть ли USER?
     - Последний USER == root / 0?
     - UID < 1000?

  3. ADD-001 / COPY-001
     - Используется ли ADD?
     - COPY . . (широкое копирование)?

  4. SECRET-001..002
     - ENV/ARG/LABEL содержат паттерны секретов?
     - RUN echo/printf с секретами?

  5. PKG-001..003
     - update отдельно от install?
     - Нет очистки apt lists?
     - Установка ssh/netcat и т.п.?

  6. HC-001
     - Есть ли HEALTHCHECK?

  7. MS-001
     - Single-stage + build-инструменты?

  8. CMD-001
     - Shell-форма вместо exec-формы?

  9. EXPOSE-001
     - Порты < 1024?

 10. WORKDIR-001 / SYNTAX-001
     - WORKDIR /
     - Нет # syntax=
```

## 4. Расширяемость

Новое правило добавляется как метод `_check_xxx(self, parsed: ParseResult)` и вызывается из `check()`.

Каждое правило создаёт объекты `Finding` с:
- rule_id
- severity
- message
- line
- recommendation
- auto_fixable + suggested_fix (опционально)

## 5. Поток данных при запуске CLI

```
main()
  → argparse
  → Path.read_text()
  → DockerfileParser.parse()
  → SecurityChecker.check()
  → ReportGenerator.generate()  или JSON
  → (опционально) AutoFixer.apply() → запись файла
  → sys.exit(0|1)  в зависимости от CRITICAL/HIGH
```

## 6. Коды возврата

| Код | Значение |
|-----|----------|
| 0   | Нет CRITICAL и HIGH замечаний |
| 1   | Есть CRITICAL или HIGH |
| 2   | Ошибка (файл не найден и т.п.) |
