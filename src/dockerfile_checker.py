#!/usr/bin/env python3
"""
Dockerfile Security Checker
Проверяет Dockerfile на соответствие best practices и требованиям информационной безопасности.

Основано на:
- CIS Docker Benchmark (Section 4)
- Docker Official Best Practices
- OWASP Docker Security Cheat Sheet

Возможности:
- 20+ правил безопасности
- Игнорирование правил: # check: ignore RULE-ID
- Автофикс: ADD→COPY, добавление non-root USER
- Отчёты: текст, JSON, SARIF
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    line: Optional[int] = None
    recommendation: str = ""
    auto_fixable: bool = False
    suggested_fix: Optional[str] = None


@dataclass
class Instruction:
    """Одна инструкция Dockerfile."""
    cmd: str
    args: str
    raw: str
    line_number: int
    is_continuation: bool = False


@dataclass
class ParseResult:
    instructions: List[Instruction] = field(default_factory=list)
    raw_lines: List[str] = field(default_factory=list)
    has_syntax_directive: bool = False
    stages: List[str] = field(default_factory=list)
    ignored_rules: Set[str] = field(default_factory=set)  # из # check: ignore


class DockerfileParser:
    """Парсер Dockerfile с поддержкой multi-line, multi-stage и ignore-комментариев."""

    INSTRUCTION_RE = re.compile(
        r"^\s*(FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|"
        r"VOLUME|USER|WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\s+(.*)$",
        re.IGNORECASE,
    )
    # # check: ignore RULE-001  или  # check:ignore RULE-001,RULE-002
    IGNORE_RE = re.compile(
        r"#\s*check\s*:\s*ignore\s+([A-Za-z0-9_,\-\s]+)",
        re.IGNORECASE,
    )

    def parse(self, content: str) -> ParseResult:
        result = ParseResult()
        lines = content.splitlines()
        result.raw_lines = lines

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped:
                i += 1
                continue

            if stripped.startswith("#"):
                if stripped.lower().startswith("# syntax="):
                    result.has_syntax_directive = True
                # Парсим ignore-директивы
                m = self.IGNORE_RE.search(stripped)
                if m:
                    for part in re.split(r"[,\s]+", m.group(1).strip()):
                        rid = part.strip().upper()
                        if rid:
                            result.ignored_rules.add(rid)
                i += 1
                continue

            full_line = line
            line_num = i + 1
            while full_line.rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                full_line = full_line.rstrip()[:-1] + " " + lines[i].strip()

            match = self.INSTRUCTION_RE.match(full_line)
            if match:
                cmd = match.group(1).upper()
                args = match.group(2).strip()
                instr = Instruction(
                    cmd=cmd,
                    args=args,
                    raw=full_line,
                    line_number=line_num,
                )
                result.instructions.append(instr)

                if cmd == "FROM":
                    as_match = re.search(r"\bAS\s+(\w+)", args, re.IGNORECASE)
                    if as_match:
                        result.stages.append(as_match.group(1))
                    else:
                        result.stages.append(f"stage_{len(result.stages)}")

            i += 1

        return result


class SecurityChecker:
    """Набор правил проверки Dockerfile."""

    SECRET_PATTERNS = [
        re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth)"),
        re.compile(r"(?i)(aws_access|aws_secret|db_pass|mysql_pwd|redis_pass)"),
    ]

    SUSPICIOUS_PACKAGES = {"ssh", "openssh", "openssh-server", "telnet", "netcat", "nc", "nmap"}

    TRUSTED_BASE_PREFIXES = (
        "alpine", "debian", "ubuntu", "scratch", "busybox",
        "python", "node", "golang", "go", "openjdk", "eclipse-temurin",
        "gcr.io/distroless", "cgr.dev/", "docker.io/library/",
        "public.ecr.aws/", "mcr.microsoft.com/", "registry.access.redhat.com/",
        "quay.io/", "ghcr.io/",
    )

    def __init__(self, enable_autofix: bool = False):
        self.enable_autofix = enable_autofix
        self.findings: List[Finding] = []
        self._ignored: Set[str] = set()

    def check(self, parsed: ParseResult) -> List[Finding]:
        self.findings = []
        self._ignored = {r.upper() for r in parsed.ignored_rules}

        self._check_from(parsed)
        self._check_user(parsed)
        self._check_copy_add(parsed)
        self._check_secrets(parsed)
        self._check_packages(parsed)
        self._check_healthcheck(parsed)
        self._check_multi_stage(parsed)
        self._check_cmd_entrypoint(parsed)
        self._check_expose(parsed)
        self._check_workdir(parsed)
        self._check_syntax(parsed)

        # Фильтруем проигнорированные правила
        if self._ignored:
            self.findings = [
                f for f in self.findings
                if f.rule_id.upper() not in self._ignored
            ]
        return self.findings

    def _add(self, finding: Finding) -> None:
        """Добавить finding, если правило не в ignore-списке (ранняя проверка)."""
        if finding.rule_id.upper() in self._ignored:
            return
        self.findings.append(finding)

    # ---------- Правила ----------

    def _check_from(self, parsed: ParseResult):
        froms = [i for i in parsed.instructions if i.cmd == "FROM"]
        if not froms:
            self._add(Finding(
                rule_id="FROM-001",
                severity=Severity.CRITICAL,
                message="Отсутствует инструкция FROM",
                recommendation="Добавьте FROM с доверенным базовым образом.",
            ))
            return

        for instr in froms:
            args = instr.args.strip()
            image_part = re.split(r"\s+AS\s+", args, flags=re.IGNORECASE)[0].strip()

            if re.search(r":latest(\s|$)", image_part) or (
                ":" not in image_part and "@" not in image_part and image_part.lower() != "scratch"
            ):
                if ":" not in image_part and "@" not in image_part and image_part.lower() != "scratch":
                    self._add(Finding(
                        rule_id="FROM-002",
                        severity=Severity.HIGH,
                        message=f"Базовый образ без явного тега (подразумевается :latest): {image_part}",
                        line=instr.line_number,
                        recommendation="Укажите конкретный тег версии, например alpine:3.20",
                    ))
                elif ":latest" in image_part:
                    self._add(Finding(
                        rule_id="FROM-002",
                        severity=Severity.HIGH,
                        message=f"Используется тег :latest: {image_part}",
                        line=instr.line_number,
                        recommendation="Замените :latest на конкретную версию и по возможности добавьте digest (@sha256:...).",
                    ))

            if "@sha256:" not in image_part and image_part.lower() != "scratch":
                self._add(Finding(
                    rule_id="FROM-003",
                    severity=Severity.MEDIUM,
                    message=f"Рекомендуется фиксировать digest: {image_part}",
                    line=instr.line_number,
                    recommendation="Добавьте @sha256:<digest> для полной воспроизводимости.",
                ))

            lower = image_part.lower()
            is_trusted = any(lower.startswith(p) or f"/{p}" in lower for p in self.TRUSTED_BASE_PREFIXES)
            if not is_trusted and not lower.startswith(("library/",)):
                self._add(Finding(
                    rule_id="FROM-004",
                    severity=Severity.MEDIUM,
                    message=f"Базовый образ может быть недоверенным: {image_part}",
                    line=instr.line_number,
                    recommendation="Используйте Docker Official Images, Verified Publisher или Hardened Images.",
                ))

    def _check_user(self, parsed: ParseResult):
        users = [i for i in parsed.instructions if i.cmd == "USER"]
        last_user = users[-1] if users else None

        if not users:
            # Определяем, какой синтаксис useradd подходит по базовому образу
            from_args = " ".join(
                i.args.lower() for i in parsed.instructions if i.cmd == "FROM"
            )
            if "alpine" in from_args or "busybox" in from_args:
                create_user = (
                    "RUN addgroup -g 10001 -S appgroup && "
                    "adduser -u 10001 -S appuser -G appgroup"
                )
            else:
                create_user = (
                    "RUN groupadd -r appgroup && "
                    "useradd -r -g appgroup -u 10001 appuser"
                )
            suggested = f"{create_user}\nUSER 10001:10001"

            self._add(Finding(
                rule_id="USER-001",
                severity=Severity.HIGH,
                message="Отсутствует инструкция USER — контейнер будет работать от root",
                recommendation="Создайте non-root пользователя и добавьте USER <uid>:<gid> перед CMD/ENTRYPOINT.",
                auto_fixable=True,
                suggested_fix=suggested,
            ))
        else:
            user_arg = last_user.args.strip().split()[0] if last_user.args else ""
            if user_arg in ("0", "root", "0:0", "root:root"):
                self._add(Finding(
                    rule_id="USER-002",
                    severity=Severity.HIGH,
                    message=f"Последний USER указывает на root: {user_arg}",
                    line=last_user.line_number,
                    recommendation="Укажите non-root пользователя (UID ≥ 1000).",
                ))
            uid_match = re.match(r"^(\d+)", user_arg)
            if uid_match:
                uid = int(uid_match.group(1))
                if 0 < uid < 1000:
                    self._add(Finding(
                        rule_id="USER-003",
                        severity=Severity.MEDIUM,
                        message=f"UID {uid} < 1000 — возможное пересечение с системными пользователями хоста",
                        line=last_user.line_number,
                        recommendation="Используйте UID ≥ 1000 (лучше ≥ 10000).",
                    ))

    def _check_copy_add(self, parsed: ParseResult):
        for instr in parsed.instructions:
            if instr.cmd == "ADD":
                fixed = re.sub(r"\bADD\b", "COPY", instr.raw, count=1, flags=re.IGNORECASE)
                self._add(Finding(
                    rule_id="ADD-001",
                    severity=Severity.HIGH,
                    message="Используется ADD вместо COPY",
                    line=instr.line_number,
                    recommendation="Замените ADD на COPY (ADD имеет неявное поведение: remote URL, распаковка архивов).",
                    auto_fixable=True,
                    suggested_fix=fixed,
                ))
            if instr.cmd in ("COPY", "ADD"):
                args = instr.args.strip()
                if re.match(r"^\.\s+\.\s*$", args) or args.startswith(". "):
                    self._add(Finding(
                        rule_id="COPY-001",
                        severity=Severity.MEDIUM,
                        message="Широкое копирование (COPY . .) — риск попадания лишних файлов",
                        line=instr.line_number,
                        recommendation="Копируйте только необходимые файлы/директории и используйте .dockerignore.",
                    ))

    def _check_secrets(self, parsed: ParseResult):
        for instr in parsed.instructions:
            if instr.cmd in ("ENV", "ARG", "LABEL"):
                for pattern in self.SECRET_PATTERNS:
                    if pattern.search(instr.args):
                        self._add(Finding(
                            rule_id="SECRET-001",
                            severity=Severity.CRITICAL,
                            message=f"Возможный секрет в {instr.cmd}: {instr.args[:80]}...",
                            line=instr.line_number,
                            recommendation="Никогда не храните секреты в Dockerfile. Используйте BuildKit secrets (--mount=type=secret) или runtime secrets.",
                        ))
                        break

            if instr.cmd == "RUN":
                if re.search(r"(?i)(echo|printf).*(password|secret|token|key)\s*=", instr.args):
                    self._add(Finding(
                        rule_id="SECRET-002",
                        severity=Severity.CRITICAL,
                        message="Возможная запись секрета в файл через RUN echo/printf",
                        line=instr.line_number,
                        recommendation="Используйте BuildKit secret mounts.",
                    ))

    def _check_packages(self, parsed: ParseResult):
        for instr in parsed.instructions:
            if instr.cmd != "RUN":
                continue
            args_lower = instr.args.lower()

            if re.search(r"\b(apt-get|apt)\s+update\b", args_lower) and not re.search(
                r"\b(install|upgrade)\b", args_lower
            ):
                self._add(Finding(
                    rule_id="PKG-001",
                    severity=Severity.HIGH,
                    message="apt-get/apt update выполняется отдельно от install",
                    line=instr.line_number,
                    recommendation="Объедините update + install + clean в одном RUN (CIS 4.7).",
                ))

            if re.search(r"\bapk\s+update\b", args_lower) and "add" not in args_lower:
                self._add(Finding(
                    rule_id="PKG-001",
                    severity=Severity.HIGH,
                    message="apk update выполняется отдельно от add",
                    line=instr.line_number,
                    recommendation="Используйте apk add --no-cache ...",
                ))

            if re.search(r"\b(apt-get|apt)\s+install\b", args_lower):
                if "rm -rf /var/lib/apt/lists" not in args_lower:
                    self._add(Finding(
                        rule_id="PKG-002",
                        severity=Severity.MEDIUM,
                        message="После apt install рекомендуется удалять /var/lib/apt/lists/* в том же слое",
                        line=instr.line_number,
                        recommendation="Добавьте && rm -rf /var/lib/apt/lists/*",
                    ))

            for pkg in self.SUSPICIOUS_PACKAGES:
                if re.search(rf"\b{re.escape(pkg)}\b", args_lower):
                    self._add(Finding(
                        rule_id="PKG-003",
                        severity=Severity.HIGH,
                        message=f"Установка потенциально опасного/ненужного пакета: {pkg}",
                        line=instr.line_number,
                        recommendation="Не устанавливайте ssh-сервер, netcat и подобные утилиты в production-образ.",
                    ))

    def _check_healthcheck(self, parsed: ParseResult):
        if not any(i.cmd == "HEALTHCHECK" for i in parsed.instructions):
            self._add(Finding(
                rule_id="HC-001",
                severity=Severity.MEDIUM,
                message="Отсутствует HEALTHCHECK",
                recommendation="Добавьте HEALTHCHECK для возможности оркестратора определять состояние контейнера (CIS 4.6).",
            ))

    def _check_multi_stage(self, parsed: ParseResult):
        froms = [i for i in parsed.instructions if i.cmd == "FROM"]
        if len(froms) < 2:
            run_text = " ".join(i.args.lower() for i in parsed.instructions if i.cmd == "RUN")
            build_tools = ["gcc", "g++", "make", "cmake", "go build", "npm install", "pip install", "maven", "gradle"]
            if any(t in run_text for t in build_tools):
                self._add(Finding(
                    rule_id="MS-001",
                    severity=Severity.MEDIUM,
                    message="Обнаружены build-команды в single-stage Dockerfile",
                    recommendation="Используйте multi-stage build: собирайте в builder-stage, копируйте только артефакты в минимальный runtime-stage.",
                ))

    def _check_cmd_entrypoint(self, parsed: ParseResult):
        for instr in parsed.instructions:
            if instr.cmd in ("CMD", "ENTRYPOINT"):
                args = instr.args.strip()
                if not (args.startswith("[") and args.endswith("]")):
                    self._add(Finding(
                        rule_id="CMD-001",
                        severity=Severity.LOW,
                        message=f"{instr.cmd} использует shell-форму",
                        line=instr.line_number,
                        recommendation='Предпочитайте exec-форму: CMD ["executable", "param"] — корректная обработка сигналов.',
                    ))

    def _check_expose(self, parsed: ParseResult):
        for instr in parsed.instructions:
            if instr.cmd == "EXPOSE":
                for p in re.findall(r"\b(\d+)\b", instr.args):
                    port = int(p)
                    if port < 1024:
                        self._add(Finding(
                            rule_id="EXPOSE-001",
                            severity=Severity.LOW,
                            message=f"EXPOSE привилегированного порта {port}",
                            line=instr.line_number,
                            recommendation="По возможности используйте порты ≥ 1024.",
                        ))

    def _check_workdir(self, parsed: ParseResult):
        for instr in parsed.instructions:
            if instr.cmd == "WORKDIR":
                path = instr.args.strip().split()[0] if instr.args else ""
                if path == "/":
                    self._add(Finding(
                        rule_id="WORKDIR-001",
                        severity=Severity.LOW,
                        message="WORKDIR установлен в корень /",
                        line=instr.line_number,
                        recommendation="Используйте выделенную директорию, например /app.",
                    ))

    def _check_syntax(self, parsed: ParseResult):
        if not parsed.has_syntax_directive:
            self._add(Finding(
                rule_id="SYNTAX-001",
                severity=Severity.INFO,
                message="Отсутствует директива # syntax=docker/dockerfile:...",
                recommendation="Добавьте # syntax=docker/dockerfile:1 в начало файла для доступа к современным возможностям BuildKit.",
            ))


class ReportGenerator:
    """Формирование текстового отчёта."""

    SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    def generate(self, findings: List[Finding], dockerfile_path: str) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append(f"Dockerfile Security Report: {dockerfile_path}")
        lines.append("=" * 70)
        lines.append("")

        if not findings:
            lines.append("✅ Нарушений не обнаружено. Dockerfile соответствует выбранным best practices.")
            return "\n".join(lines)

        sorted_findings = sorted(findings, key=lambda f: self.SEVERITY_ORDER[f.severity])
        counts: Dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        lines.append("Сводка:")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if sev in counts:
                lines.append(f"  {sev.value}: {counts[sev]}")
        lines.append("")

        lines.append("-" * 70)
        for i, f in enumerate(sorted_findings, 1):
            loc = f" (строка {f.line})" if f.line else ""
            lines.append(f"{i}. [{f.severity.value}] {f.rule_id}{loc}")
            lines.append(f"   {f.message}")
            if f.recommendation:
                lines.append(f"   → Рекомендация: {f.recommendation}")
            if f.auto_fixable and f.suggested_fix:
                preview = f.suggested_fix.replace("\n", " | ")
                lines.append(f"   → Автоисправление: {preview}")
            lines.append("")

        lines.append("-" * 70)
        lines.append(f"Всего замечаний: {len(findings)}")
        return "\n".join(lines)


class SarifGenerator:
    """Генерация отчёта в формате SARIF 2.1.0 (для GitHub Code Scanning и др.)."""

    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    def generate(self, findings: List[Finding], dockerfile_path: str) -> dict:
        rules_map: Dict[str, dict] = {}
        results = []

        for f in findings:
            if f.rule_id not in rules_map:
                rules_map[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.message[:120]},
                    "fullDescription": {"text": f.recommendation or f.message},
                    "defaultConfiguration": {
                        "level": self.SEVERITY_TO_LEVEL.get(f.severity, "warning")
                    },
                    "properties": {
                        "security-severity": {
                            Severity.CRITICAL: "9.0",
                            Severity.HIGH: "7.0",
                            Severity.MEDIUM: "5.0",
                            Severity.LOW: "3.0",
                            Severity.INFO: "1.0",
                        }.get(f.severity, "5.0")
                    },
                }

            result: dict = {
                "ruleId": f.rule_id,
                "level": self.SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [],
            }
            if f.line:
                result["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": dockerfile_path},
                        "region": {"startLine": f.line},
                    }
                })
            else:
                result["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": dockerfile_path},
                    }
                })
            if f.recommendation:
                result["message"]["text"] = f"{f.message}. {f.recommendation}"
            results.append(result)

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Dockerfile Security Checker",
                            "version": "1.1.0",
                            "informationUri": "https://github.com/example/dockerfile-security-checker",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }


class AutoFixer:
    """Автоматические исправления: ADD→COPY, добавление non-root USER."""

    def apply(self, content: str, findings: List[Finding], parsed: ParseResult) -> Tuple[str, int]:
        lines = content.splitlines()
        applied = 0

        # 1) ADD → COPY (по номерам строк, с конца, чтобы индексы не съезжали)
        add_fixes = [
            f for f in findings
            if f.rule_id == "ADD-001" and f.auto_fixable and f.line
        ]
        for f in sorted(add_fixes, key=lambda x: x.line or 0, reverse=True):
            idx = (f.line or 1) - 1
            if 0 <= idx < len(lines) and re.search(r"\bADD\b", lines[idx], re.IGNORECASE):
                lines[idx] = re.sub(r"\bADD\b", "COPY", lines[idx], count=1, flags=re.IGNORECASE)
                applied += 1

        # 2) USER-001: вставить создание пользователя + USER перед CMD/ENTRYPOINT
        user_fix = next(
            (f for f in findings if f.rule_id == "USER-001" and f.auto_fixable and f.suggested_fix),
            None,
        )
        if user_fix:
            # Ищем последнюю строку CMD/ENTRYPOINT или конец файла
            insert_at = len(lines)
            for i in range(len(lines) - 1, -1, -1):
                s = lines[i].strip().upper()
                if s.startswith("CMD ") or s.startswith("ENTRYPOINT ") or s.startswith("CMD\t") or s.startswith("ENTRYPOINT\t"):
                    insert_at = i
                    break

            block = user_fix.suggested_fix.split("\n")
            # Пустая строка перед блоком для читаемости
            new_block = [""] + block + [""]
            lines[insert_at:insert_at] = new_block
            applied += 1

        fixed = "\n".join(lines)
        if content.endswith("\n") and not fixed.endswith("\n"):
            fixed += "\n"
        return fixed, applied


def main():
    parser = argparse.ArgumentParser(
        description="Dockerfile Security Checker — проверка на соответствие best practices и ИБ-требованиям",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python dockerfile_checker.py Dockerfile
  python dockerfile_checker.py -f tests/dockerfiles/bad_root.Dockerfile --json
  python dockerfile_checker.py Dockerfile --fix -o Dockerfile.fixed
  python dockerfile_checker.py Dockerfile --sarif report.sarif

Игнорирование правил в Dockerfile:
  # check: ignore SECRET-001
  # check: ignore FROM-003, HC-001
        """,
    )
    parser.add_argument("dockerfile", nargs="?", default="Dockerfile", help="Путь к Dockerfile")
    parser.add_argument("-f", "--file", dest="dockerfile_opt", help="Альтернативный способ указать файл")
    parser.add_argument("--fix", action="store_true", help="Автоматически исправить простые нарушения (ADD→COPY, USER)")
    parser.add_argument("-o", "--output", help="Путь для сохранения исправленного файла")
    parser.add_argument("--json", action="store_true", help="Вывод в JSON")
    parser.add_argument("--sarif", metavar="FILE", help="Сохранить отчёт в формате SARIF 2.1.0")
    parser.add_argument("-q", "--quiet", action="store_true", help="Только код возврата и краткая сводка")

    args = parser.parse_args()
    path = Path(args.dockerfile_opt or args.dockerfile)

    if not path.exists():
        print(f"Ошибка: файл не найден: {path}", file=sys.stderr)
        sys.exit(2)

    content = path.read_text(encoding="utf-8", errors="replace")
    parser_obj = DockerfileParser()
    parsed = parser_obj.parse(content)

    checker = SecurityChecker(enable_autofix=args.fix)
    findings = checker.check(parsed)

    if args.json:
        data = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "line": f.line,
                "recommendation": f.recommendation,
                "auto_fixable": f.auto_fixable,
            }
            for f in findings
        ]
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif not args.quiet:
        report = ReportGenerator().generate(findings, str(path))
        print(report)
        if parsed.ignored_rules:
            print(f"\nПроигнорированные правила: {', '.join(sorted(parsed.ignored_rules))}")

    if args.sarif:
        sarif = SarifGenerator().generate(findings, str(path))
        sarif_path = Path(args.sarif)
        sarif_path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"\nSARIF-отчёт сохранён: {sarif_path}")

    if args.fix:
        fixer = AutoFixer()
        fixed_content, count = fixer.apply(content, findings, parsed)
        out_path = Path(args.output) if args.output else path.with_suffix(path.suffix + ".fixed")
        out_path.write_text(fixed_content, encoding="utf-8")
        if not args.quiet:
            print(f"\nАвтоисправлений применено: {count}. Результат сохранён в {out_path}")

    has_serious = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    sys.exit(1 if has_serious else 0)


if __name__ == "__main__":
    main()
