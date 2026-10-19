"""Presentación de resultados en texto (terminal) y JSON."""

from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .models import ScanResult, Severity

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLORS = {
    Severity.HIGH: "\033[31m",  # rojo
    Severity.MEDIUM: "\033[33m",  # amarillo
    Severity.LOW: "\033[36m",  # cian
    Severity.INFO: "\033[34m",  # azul
    Severity.PASS: "\033[32m",  # verde
}
_GRADE_COLORS = {"A+": "\033[32m", "A": "\033[32m", "B": "\033[33m", "C": "\033[33m"}


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + _RESET


def render_text(results: list[ScanResult], color: bool = False) -> str:
    style = _Style(color)
    blocks = [_render_result(r, style) for r in results]
    return "\n\n".join(blocks) + "\n"


def _render_result(result: ScanResult, style: _Style) -> str:
    lines = [style(result.url, _BOLD)]

    if result.error or result.target is None:
        lines.append(style(f"  Error: {result.error}", _COLORS[Severity.HIGH]))
        return "\n".join(lines)

    target = result.target
    if target.final_url.rstrip("/") != target.url.rstrip("/"):
        lines.append(style(f"  → {target.final_url}", _DIM))
    grade_color = _GRADE_COLORS.get(result.grade, _COLORS[Severity.HIGH])
    lines.append(
        f"  HTTP {target.status_code} · Nota: "
        + style(result.grade, _BOLD, grade_color)
        + f" ({result.score}/100)"
    )
    lines.append("")

    header_width = max((len(f.header) for f in result.findings), default=0)
    for f in result.findings:
        label = style(f"{f.severity.label:<5}", _COLORS[f.severity])
        lines.append(f"  {label}  {f.header:<{header_width}}  {f.title}")
        indent = " " * (2 + 5 + 2 + header_width + 2)
        if f.detail and f.severity is not Severity.PASS:
            lines.append(style(f"{indent}{f.detail}", _DIM))
        if f.recommendation and f.severity is not Severity.PASS:
            lines.append(f"{indent}↳ {f.recommendation}")

    lines.append("")
    lines.append("  " + _summary(result))
    return "\n".join(lines)


def _summary(result: ScanResult) -> str:
    counts = Counter(f.severity for f in result.findings)
    parts = [
        f"{counts[s]} {s.label.lower()}"
        for s in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    ]
    parts.append(f"{counts[Severity.PASS]} correctas")
    return "Resumen: " + ", ".join(parts)


def render_json(results: list[ScanResult]) -> str:
    payload = {
        "tool": "header-auditor",
        "version": __version__,
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
