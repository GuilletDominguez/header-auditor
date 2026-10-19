"""Cálculo de la puntuación (0-100) y la nota (A+ a F)."""

from __future__ import annotations

from .models import Finding, Severity

# Puntos que resta cada hallazgo según su gravedad.
PENALTIES = {
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
    Severity.PASS: 0,
}

# Nota mínima para cada letra, de mayor a menor.
GRADES = (
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (0, "F"),
)


def score(findings: list[Finding]) -> int:
    """Parte de 100 y resta la penalización de cada hallazgo, sin bajar de 0."""
    return max(0, 100 - sum(PENALTIES[f.severity] for f in findings))


def grade(points: int) -> str:
    for minimum, letter in GRADES:
        if points >= minimum:
            return letter
    return "F"
