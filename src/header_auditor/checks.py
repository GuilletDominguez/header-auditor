"""Comprobaciones de seguridad sobre las cabeceras de una respuesta.

Cada comprobación es una función pura: recibe un ``Target`` y devuelve una lista
de ``Finding``. No hace peticiones ni imprime nada, así que se puede testear con
cabeceras inventadas.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .models import Finding, Severity, Target

Check = Callable[[Target], list[Finding]]

CHECKS: list[Check] = []


def check(func: Check) -> Check:
    """Registra una función como comprobación."""
    CHECKS.append(func)
    return func


def run_checks(target: Target) -> list[Finding]:
    """Ejecuta todas las comprobaciones y ordena los hallazgos de más a menos grave."""
    findings = [finding for func in CHECKS for finding in func(target)]
    return sorted(findings, key=lambda f: f.severity, reverse=True)


# --------------------------------------------------------------------------- #
# Utilidades de parseo
# --------------------------------------------------------------------------- #


def parse_csp(value: str) -> dict[str, list[str]]:
    """Convierte una política CSP en {directiva: [fuentes]}.

    Si una directiva se repite, el navegador usa la primera y descarta el resto.
    Si la cabecera trae varias políticas separadas por comas, se analiza la
    primera.
    """
    directives: dict[str, list[str]] = {}
    for part in value.split(",")[0].split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives.setdefault(name, [t.lower() for t in tokens[1:]])
    return directives


def _parse_directives(value: str) -> dict[str, str]:
    """Parsea cabeceras con formato ``clave=valor; clave2`` (HSTS, cookies)."""
    result: dict[str, str] = {}
    for part in value.split(";"):
        key, _, val = part.strip().partition("=")
        if key:
            result[key.strip().lower()] = val.strip().strip('"')
    return result


# --------------------------------------------------------------------------- #
# Transporte
# --------------------------------------------------------------------------- #

SIX_MONTHS = 15_552_000  # segundos; mínimo habitual recomendado para HSTS


@check
def check_https(t: Target) -> list[Finding]:
    if t.is_https:
        return [Finding("HTTPS", Severity.PASS, "La web se sirve por HTTPS")]
    return [
        Finding(
            "HTTPS",
            Severity.HIGH,
            "La web se sirve sin cifrar (HTTP)",
            detail=f"La respuesta final llega desde {t.final_url}.",
            recommendation="Sirve la web solo por HTTPS y redirige todo el tráfico HTTP a HTTPS.",
        )
    ]


@check
def check_hsts(t: Target) -> list[Finding]:
    name = "Strict-Transport-Security"
    if not t.is_https:
        # Los navegadores ignoran HSTS si llega por HTTP; el problema ya lo
        # reporta check_https.
        return []

    value = t.get(name)
    if value is None:
        return [
            Finding(
                name,
                Severity.HIGH,
                "Falta la cabecera",
                detail="Sin HSTS, un atacante en la red puede forzar la primera visita por HTTP "
                "(SSL stripping).",
                recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
            )
        ]

    directives = _parse_directives(value)
    raw_max_age = directives.get("max-age", "")
    if not raw_max_age.isdigit():
        return [
            Finding(
                name,
                Severity.MEDIUM,
                "max-age ausente o inválido",
                detail=f"Valor recibido: {value}",
                recommendation="Indica un max-age numérico de al menos 15552000 (6 meses).",
            )
        ]

    max_age = int(raw_max_age)
    if max_age == 0:
        return [
            Finding(
                name,
                Severity.HIGH,
                "max-age=0 desactiva HSTS",
                recommendation="Usa max-age=31536000 (1 año).",
            )
        ]

    findings = []
    if max_age < SIX_MONTHS:
        findings.append(
            Finding(
                name,
                Severity.MEDIUM,
                "max-age demasiado bajo",
                detail=f"max-age={max_age} ({max_age // 86400} días).",
                recommendation="Usa al menos 15552000 (6 meses); lo habitual es 31536000 (1 año).",
            )
        )
    if "includesubdomains" not in directives:
        findings.append(
            Finding(
                name,
                Severity.LOW,
                "Sin includeSubDomains",
                detail="Los subdominios no quedan protegidos por HSTS.",
                recommendation="Añade includeSubDomains si todos los subdominios usan HTTPS.",
            )
        )
    if not findings:
        detail = "Incluida la directiva preload." if "preload" in directives else ""
        findings.append(Finding(name, Severity.PASS, "Configuración correcta", detail=detail))
    return findings


# --------------------------------------------------------------------------- #
# Content Security Policy
# --------------------------------------------------------------------------- #

_PERMISSIVE_SOURCES = {"*", "http:", "https:", "data:"}


@check
def check_csp(t: Target) -> list[Finding]:
    name = "Content-Security-Policy"
    value = t.get(name)
    if value is None:
        if t.get("Content-Security-Policy-Report-Only") is not None:
            return [
                Finding(
                    name,
                    Severity.MEDIUM,
                    "Solo existe en modo Report-Only",
                    detail="La política informa de violaciones pero no bloquea nada.",
                    recommendation="Cuando la política esté probada, envíala como "
                    "Content-Security-Policy.",
                )
            ]
        return [
            Finding(
                name,
                Severity.HIGH,
                "Falta la cabecera",
                detail="Sin CSP el navegador ejecuta cualquier script inyectado (XSS).",
                recommendation="Empieza por: default-src 'self'; object-src 'none'; "
                "frame-ancestors 'self'",
            )
        ]

    csp = parse_csp(value)
    findings = []
    script_src = csp.get("script-src", csp.get("default-src"))

    if script_src is None:
        findings.append(
            Finding(
                name,
                Severity.MEDIUM,
                "No restringe los scripts",
                detail="No hay script-src ni default-src, así que se permite cargar scripts "
                "de cualquier origen.",
                recommendation="Define default-src 'self' o un script-src explícito.",
            )
        )
    else:
        # Si hay nonce o hash, los navegadores modernos ignoran 'unsafe-inline'.
        has_nonce_or_hash = any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script_src
        )
        if "'unsafe-inline'" in script_src and not has_nonce_or_hash:
            findings.append(
                Finding(
                    name,
                    Severity.MEDIUM,
                    "Permite scripts en línea ('unsafe-inline')",
                    detail="Un XSS puede ejecutar código directamente en la página.",
                    recommendation="Usa nonces o hashes en lugar de 'unsafe-inline'.",
                )
            )
        if "'unsafe-eval'" in script_src:
            findings.append(
                Finding(
                    name,
                    Severity.MEDIUM,
                    "Permite eval() ('unsafe-eval')",
                    recommendation="Elimina 'unsafe-eval' y evita eval()/new Function().",
                )
            )
        permissive = sorted(_PERMISSIVE_SOURCES.intersection(script_src))
        if permissive:
            findings.append(
                Finding(
                    name,
                    Severity.MEDIUM,
                    "Orígenes de script demasiado amplios",
                    detail=f"Fuentes permisivas: {' '.join(permissive)}",
                    recommendation="Limita los scripts a 'self' y a dominios concretos.",
                )
            )

    object_src = csp.get("object-src", csp.get("default-src"))
    if object_src is None or "*" in object_src:
        findings.append(
            Finding(
                name,
                Severity.LOW,
                "object-src sin restringir",
                detail="Permite incrustar plugins (<object>, <embed>).",
                recommendation="Añade object-src 'none'.",
            )
        )

    if not findings:
        findings.append(Finding(name, Severity.PASS, "Política sin debilidades evidentes"))
    return findings


# --------------------------------------------------------------------------- #
# Cabeceras de protección del navegador
# --------------------------------------------------------------------------- #


@check
def check_clickjacking(t: Target) -> list[Finding]:
    name = "X-Frame-Options"
    csp_value = t.get("Content-Security-Policy")
    if csp_value and "frame-ancestors" in parse_csp(csp_value):
        return [Finding(name, Severity.PASS, "Protegido mediante CSP frame-ancestors")]

    value = t.get(name)
    if value is None:
        return [
            Finding(
                name,
                Severity.MEDIUM,
                "Sin protección contra clickjacking",
                detail="No hay X-Frame-Options ni CSP frame-ancestors: otra web puede cargar "
                "esta en un iframe.",
                recommendation="X-Frame-Options: DENY (o CSP frame-ancestors 'self').",
            )
        ]

    normalized = value.strip().upper()
    if normalized in ("DENY", "SAMEORIGIN"):
        return [Finding(name, Severity.PASS, f"Configurada como {normalized}")]
    if normalized.startswith("ALLOW-FROM"):
        return [
            Finding(
                name,
                Severity.LOW,
                "ALLOW-FROM está obsoleto",
                detail="Los navegadores actuales lo ignoran, así que la página queda sin proteger.",
                recommendation="Usa CSP frame-ancestors para permitir orígenes concretos.",
            )
        ]
    return [
        Finding(
            name,
            Severity.LOW,
            "Valor no válido",
            detail=f"Valor recibido: {value}",
            recommendation="Usa DENY o SAMEORIGIN.",
        )
    ]


@check
def check_content_type_options(t: Target) -> list[Finding]:
    name = "X-Content-Type-Options"
    value = t.get(name)
    if value is None:
        return [
            Finding(
                name,
                Severity.MEDIUM,
                "Falta la cabecera",
                detail="El navegador puede interpretar un archivo con un tipo distinto al "
                "declarado (MIME sniffing).",
                recommendation="X-Content-Type-Options: nosniff",
            )
        ]
    if value.strip().lower() != "nosniff":
        return [
            Finding(
                name,
                Severity.LOW,
                "Valor no válido",
                detail=f"Valor recibido: {value}",
                recommendation="El único valor válido es nosniff.",
            )
        ]
    return [Finding(name, Severity.PASS, "Configurada como nosniff")]


_SAFE_REFERRER = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin",
    "origin-when-cross-origin",
}
_WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


@check
def check_referrer_policy(t: Target) -> list[Finding]:
    name = "Referrer-Policy"
    value = t.get(name)
    if value is None:
        return [
            Finding(
                name,
                Severity.LOW,
                "Falta la cabecera",
                detail="El navegador usará su política por defecto al enviar la URL de origen "
                "a otras webs.",
                recommendation="Referrer-Policy: strict-origin-when-cross-origin",
            )
        ]

    # Con varios valores, el navegador aplica el último que reconoce.
    tokens = [v.strip().lower() for v in value.split(",") if v.strip()]
    known = [v for v in tokens if v in _SAFE_REFERRER | _WEAK_REFERRER]
    if not known:
        return [
            Finding(
                name,
                Severity.LOW,
                "Valor no reconocido",
                detail=f"Valor recibido: {value}",
                recommendation="Usa strict-origin-when-cross-origin.",
            )
        ]
    policy = known[-1]
    if policy in _WEAK_REFERRER:
        return [
            Finding(
                name,
                Severity.LOW,
                f"Política débil ({policy})",
                detail="Envía la URL completa, con rutas y parámetros, a otros sitios.",
                recommendation="Usa strict-origin-when-cross-origin.",
            )
        ]
    return [Finding(name, Severity.PASS, f"Configurada como {policy}")]


@check
def check_permissions_policy(t: Target) -> list[Finding]:
    name = "Permissions-Policy"
    if t.get(name) is None:
        return [
            Finding(
                name,
                Severity.LOW,
                "Falta la cabecera",
                detail="No se limita el acceso a cámara, micrófono, geolocalización, etc.",
                recommendation="Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )
        ]
    return [Finding(name, Severity.PASS, "Presente")]


@check
def check_cross_origin_isolation(t: Target) -> list[Finding]:
    findings = []
    for name, recommendation in (
        ("Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy: same-origin"),
        ("Cross-Origin-Resource-Policy", "Cross-Origin-Resource-Policy: same-origin"),
    ):
        if t.get(name) is None:
            findings.append(
                Finding(
                    name,
                    Severity.INFO,
                    "Falta la cabecera",
                    detail="Ayuda a aislar la página de otros orígenes (Spectre, XS-Leaks).",
                    recommendation=recommendation,
                )
            )
        else:
            findings.append(Finding(name, Severity.PASS, "Presente"))
    return findings


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #


@check
def check_cors(t: Target) -> list[Finding]:
    name = "Access-Control-Allow-Origin"
    origin = t.get(name)
    if origin is None:
        return []

    origin = origin.strip()
    credentials = (t.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"

    if t.probe_origin and origin == t.probe_origin:
        return [
            Finding(
                name,
                Severity.HIGH if credentials else Severity.MEDIUM,
                "Refleja cualquier origen" + (" y permite credenciales" if credentials else ""),
                detail=f"El servidor devolvió el origen ficticio enviado ({t.probe_origin}).",
                recommendation="Valida el Origin contra una lista blanca de dominios permitidos.",
            )
        ]
    if origin == "null":
        return [
            Finding(
                name,
                Severity.MEDIUM,
                "Permite el origen 'null'",
                detail="Iframes con sandbox y archivos locales envían Origin: null y lo "
                "puede usar un atacante.",
                recommendation="No incluyas 'null' entre los orígenes permitidos.",
            )
        ]
    if origin == "*":
        if credentials:
            return [
                Finding(
                    name,
                    Severity.LOW,
                    "Comodín con credenciales",
                    detail="Los navegadores rechazan esta combinación, pero indica una "
                    "configuración CORS errónea.",
                    recommendation="Si necesitas credenciales, lista orígenes concretos.",
                )
            ]
        return [
            Finding(
                name,
                Severity.INFO,
                "Permite cualquier origen (*)",
                detail="Correcto para recursos públicos; revisa que no exponga datos privados.",
            )
        ]
    return [Finding(name, Severity.PASS, f"Restringido a {origin}")]


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #


@check
def check_cookies(t: Target) -> list[Finding]:
    if not t.cookies:
        return []

    findings = []
    for raw in t.cookies:
        cookie_name = raw.split("=", 1)[0].strip()
        attributes = _parse_directives(raw.split(";", 1)[1]) if ";" in raw else {}
        problems: list[tuple[Severity, str]] = []

        if "secure" not in attributes and t.is_https:
            problems.append((Severity.MEDIUM, "falta Secure (puede enviarse por HTTP)"))
        if "httponly" not in attributes:
            problems.append((Severity.LOW, "falta HttpOnly (accesible desde JavaScript)"))
        samesite = attributes.get("samesite", "").lower()
        if not samesite:
            problems.append((Severity.LOW, "falta SameSite (riesgo de CSRF)"))
        elif samesite == "none" and "secure" not in attributes:
            problems.append((Severity.MEDIUM, "SameSite=None sin Secure (el navegador la rechaza)"))

        if problems:
            findings.append(
                Finding(
                    "Set-Cookie",
                    max(sev for sev, _ in problems),
                    f"Cookie '{cookie_name}' con atributos inseguros",
                    detail="; ".join(msg for _, msg in problems),
                    recommendation="Set-Cookie: nombre=valor; Secure; HttpOnly; SameSite=Lax",
                )
            )

    if not findings:
        findings.append(
            Finding(
                "Set-Cookie",
                Severity.PASS,
                f"Las {len(t.cookies)} cookies tienen Secure, HttpOnly y SameSite",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Fugas de información y cabeceras obsoletas
# --------------------------------------------------------------------------- #

_VERSION_RE = re.compile(r"\d+(\.\d+)+")
_DISCLOSURE_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


@check
def check_information_disclosure(t: Target) -> list[Finding]:
    findings = []
    server = t.get("Server")
    if server and _VERSION_RE.search(server):
        findings.append(
            Finding(
                "Server",
                Severity.LOW,
                "Revela la versión del servidor",
                detail=f"Server: {server}",
                recommendation="Oculta la versión (en nginx: server_tokens off; en Apache: "
                "ServerTokens Prod).",
            )
        )
    for name in _DISCLOSURE_HEADERS:
        value = t.get(name)
        if value:
            findings.append(
                Finding(
                    name,
                    Severity.LOW,
                    "Revela la tecnología usada",
                    detail=f"{name}: {value}",
                    recommendation=f"Elimina la cabecera {name}.",
                )
            )
    return findings


@check
def check_deprecated(t: Target) -> list[Finding]:
    findings = []
    xss = t.get("X-XSS-Protection")
    if xss is not None and not xss.strip().startswith("0"):
        findings.append(
            Finding(
                "X-XSS-Protection",
                Severity.INFO,
                "Cabecera obsoleta activada",
                detail="El filtro XSS de los navegadores se retiró y en algunos casos "
                "introducía vulnerabilidades.",
                recommendation="Elimínala o ponla a 0, y usa CSP en su lugar.",
            )
        )
    if t.get("Public-Key-Pins") is not None:
        findings.append(
            Finding(
                "Public-Key-Pins",
                Severity.LOW,
                "HPKP está obsoleto",
                detail="Ya no lo soportan los navegadores y un error podía bloquear la web.",
                recommendation="Elimina la cabecera.",
            )
        )
    if t.get("Expect-CT") is not None:
        findings.append(
            Finding(
                "Expect-CT",
                Severity.INFO,
                "Cabecera obsoleta",
                detail="Certificate Transparency ya es obligatorio por defecto.",
                recommendation="Puedes eliminarla.",
            )
        )
    return findings
