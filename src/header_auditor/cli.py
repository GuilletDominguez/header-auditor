"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .checks import run_checks
from .fetcher import FetchError, fetch, normalize_url
from .models import ScanResult, Severity
from .report import render_json, render_text
from .scoring import grade, score

# Códigos de salida
EXIT_OK = 0
EXIT_FINDINGS = 1  # algún hallazgo alcanza el umbral de --fail-on
EXIT_USAGE = 2  # argumentos incorrectos (también lo usa argparse)
EXIT_SCAN_ERROR = 3  # alguna URL no se pudo auditar


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header-auditor",
        description="Audita las cabeceras de seguridad HTTP de una o varias webs.",
        epilog="Ejemplo: header-auditor example.com --fail-on high",
    )
    parser.add_argument(
        "urls", nargs="*", metavar="URL", help="URL a auditar (https:// por defecto)"
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        help="fichero con una URL por línea (las líneas con # se ignoran)",
    )
    parser.add_argument("--json", action="store_true", help="salida en formato JSON")
    parser.add_argument(
        "--fail-on",
        metavar="SEVERIDAD",
        choices=["low", "medium", "high"],
        help="termina con código 1 si hay hallazgos de esta gravedad o mayor (low, medium, high)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=10.0, help="segundos de espera (por defecto: 10)"
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true", help="no verificar el certificado TLS"
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=5,
        help="URLs auditadas en paralelo (por defecto: 5)",
    )
    parser.add_argument("--no-color", action="store_true", help="desactiva los colores")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def collect_urls(args: argparse.Namespace) -> list[str]:
    raw = list(args.urls)
    if args.file:
        for line in args.file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw.append(line)
    # Elimina duplicados manteniendo el orden.
    return list(dict.fromkeys(normalize_url(u) for u in raw))


def scan(url: str, timeout: float, verify: bool) -> ScanResult:
    try:
        target = fetch(url, timeout=timeout, verify=verify)
    except FetchError as exc:
        return ScanResult(url=url, error=str(exc))
    findings = run_checks(target)
    points = score(findings)
    return ScanResult(url=url, target=target, findings=findings, score=points, grade=grade(points))


def exit_code(results: list[ScanResult], fail_on: str | None) -> int:
    if fail_on:
        threshold = Severity.from_name(fail_on)
        if any(r.worst >= threshold for r in results if r.error is None):
            return EXIT_FINDINGS
    if any(r.error for r in results):
        return EXIT_SCAN_ERROR
    return EXIT_OK


def _use_color(args: argparse.Namespace) -> bool:
    # Respeta la convención NO_COLOR (https://no-color.org).
    return not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        urls = collect_urls(args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not urls:
        parser.error("indica al menos una URL o un fichero con -f")
    if args.workers < 1:
        parser.error("--workers debe ser al menos 1")

    if args.insecure:
        print("Aviso: verificación TLS desactivada (--insecure).", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=min(args.workers, len(urls))) as pool:
        results = list(pool.map(lambda u: scan(u, args.timeout, not args.insecure), urls))

    output = render_json(results) if args.json else render_text(results, color=_use_color(args))
    sys.stdout.write(output)
    return exit_code(results, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
