"""Obtención de la respuesta HTTP que se va a auditar."""

from __future__ import annotations

from urllib.parse import urlsplit

import requests
import urllib3

from . import __version__
from .models import Target

DEFAULT_USER_AGENT = (
    f"header-auditor/{__version__} (+https://github.com/GuilletDominguez/header-auditor)"
)

# Origen ficticio que se envía en la petición. Si el servidor lo devuelve en
# Access-Control-Allow-Origin, está reflejando cualquier origen (CORS inseguro).
# El dominio .invalid está reservado (RFC 2606) y nunca resolverá.
PROBE_ORIGIN = "https://header-auditor-probe.invalid"


class FetchError(Exception):
    """No se pudo obtener una respuesta de la URL."""


def normalize_url(raw: str) -> str:
    """Añade https:// si falta y valida que la URL sea http(s) con dominio."""
    url = raw.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError(f"esquema no soportado: '{parts.scheme}' (usa http o https)")
    if not parts.hostname:
        raise ValueError(f"URL sin dominio: '{raw}'")
    return url


def fetch(
    url: str,
    timeout: float = 10.0,
    verify: bool = True,
    user_agent: str = DEFAULT_USER_AGENT,
) -> Target:
    """Hace una petición GET siguiendo redirecciones y devuelve la respuesta final.

    Se usa GET y no HEAD porque algunos servidores devuelven cabeceras distintas
    a HEAD. Con ``stream=True`` no se descarga el cuerpo de la página.
    """
    request_headers = {"User-Agent": user_agent, "Origin": PROBE_ORIGIN}
    if not verify:
        # El usuario ya recibe un aviso desde la CLI; evita uno por petición.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        with requests.get(
            url,
            headers=request_headers,
            timeout=timeout,
            verify=verify,
            allow_redirects=True,
            stream=True,
        ) as resp:
            return Target(
                url=url,
                final_url=resp.url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                cookies=_raw_cookies(resp),
                probe_origin=PROBE_ORIGIN,
            )
    except requests.exceptions.SSLError as exc:
        raise FetchError(f"error TLS/certificado: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise FetchError(f"sin respuesta en {timeout:g} s") from exc
    except requests.exceptions.ConnectionError as exc:
        # El mensaje de urllib3 es muy largo; se resume el caso más habitual.
        if "NameResolutionError" in str(exc) or "Failed to resolve" in str(exc):
            raise FetchError("no se pudo resolver el dominio (DNS)") from exc
        raise FetchError("no se pudo conectar con el servidor") from exc
    except requests.exceptions.RequestException as exc:
        raise FetchError(str(exc)) from exc


def _raw_cookies(resp: requests.Response) -> list[str]:
    """Devuelve cada Set-Cookie por separado.

    ``resp.headers`` las une en una sola cadena separada por comas, así que se
    leen de la respuesta de urllib3, que las conserva una a una.
    """
    raw_headers = getattr(resp.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []
