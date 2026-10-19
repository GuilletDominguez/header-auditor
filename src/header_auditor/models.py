"""Estructuras de datos compartidas por la petición, las comprobaciones y los informes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Gravedad de un hallazgo. Es ordenable: HIGH > MEDIUM > LOW > INFO > PASS."""

    PASS = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4

    @property
    def label(self) -> str:
        return _LABELS[self]

    @classmethod
    def from_name(cls, name: str) -> Severity:
        try:
            return cls[name.upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"severidad desconocida '{name}' (válidas: {valid})") from None


_LABELS = {
    Severity.PASS: "OK",
    Severity.INFO: "INFO",
    Severity.LOW: "BAJA",
    Severity.MEDIUM: "MEDIA",
    Severity.HIGH: "ALTA",
}


@dataclass
class Finding:
    """Resultado de una comprobación sobre una cabecera."""

    header: str
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "header": self.header,
            "severity": self.severity.name.lower(),
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class Target:
    """Datos de la respuesta HTTP que necesitan las comprobaciones.

    Las claves de ``headers`` se guardan siempre en minúsculas, porque los nombres
    de cabecera no distinguen mayúsculas. ``cookies`` guarda cada ``Set-Cookie``
    por separado: unirlas con comas las rompería (las fechas de ``Expires``
    también llevan comas).
    """

    url: str
    final_url: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    probe_origin: str | None = None

    def __post_init__(self) -> None:
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        if not self.final_url:
            self.final_url = self.url

    @property
    def is_https(self) -> bool:
        return self.final_url.lower().startswith("https://")

    def get(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class ScanResult:
    """Resultado completo de auditar una URL (o el error que lo impidió)."""

    url: str
    target: Target | None = None
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = "-"
    error: str | None = None

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.PASS)

    def to_dict(self) -> dict:
        data: dict = {"url": self.url, "error": self.error}
        if self.target is not None:
            data.update(
                final_url=self.target.final_url,
                status_code=self.target.status_code,
                score=self.score,
                grade=self.grade,
                findings=[f.to_dict() for f in self.findings],
            )
        return data
