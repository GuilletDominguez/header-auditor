# header-auditor

[![CI](https://github.com/GuilletDominguez/header-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/GuilletDominguez/header-auditor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Licencia](https://img.shields.io/badge/licencia-MIT-green)

Herramienta de línea de comandos en Python que audita las **cabeceras de seguridad HTTP** de una web, puntúa su configuración y da recomendaciones concretas para mejorarla.

No se limita a comprobar si cada cabecera existe: **analiza sus valores** para detectar configuraciones débiles (una CSP con `'unsafe-inline'`, un HSTS de pocos días, cookies sin `Secure`, CORS que refleja cualquier origen…).

```
$ header-auditor example.com

https://example.com
  HTTP 200 · Nota: F (30/100)

  ALTA   Strict-Transport-Security     Falta la cabecera
                                       Sin HSTS, un atacante en la red puede forzar la primera visita por HTTP (SSL stripping).
                                       ↳ Strict-Transport-Security: max-age=31536000; includeSubDomains
  ALTA   Content-Security-Policy       Falta la cabecera
                                       Sin CSP el navegador ejecuta cualquier script inyectado (XSS).
                                       ↳ Empieza por: default-src 'self'; object-src 'none'; frame-ancestors 'self'
  MEDIA  X-Frame-Options               Sin protección contra clickjacking
  ...
  OK     HTTPS                         La web se sirve por HTTPS

  Resumen: 2 alta, 2 media, 2 baja, 2 info, 1 correctas
```

## Características

- Más de 10 comprobaciones que analizan el **valor** de cada cabecera, no solo si está presente.
- **Detección activa de CORS mal configurado**: envía un `Origin` ficticio y comprueba si el servidor lo refleja.
- Análisis individual de cada `Set-Cookie` (`Secure`, `HttpOnly`, `SameSite`).
- Nota global de **A+ a F** y recomendación concreta para cada hallazgo.
- Salida en **terminal con colores** o en **JSON** para procesarla con otras herramientas.
- **Integrable en CI/CD** con `--fail-on`: falla el pipeline si aparecen hallazgos de cierta gravedad.
- Varias URLs a la vez (en paralelo) o desde un fichero.
- Una sola dependencia (`requests`) y tests que no necesitan conexión a internet.

## Instalación

Requiere Python 3.10 o superior.

```bash
git clone https://github.com/GuilletDominguez/header-auditor.git
cd header-auditor
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

## Uso

```bash
# Una web (si no indicas esquema se usa https://)
header-auditor example.com

# Varias webs
header-auditor example.com github.com https://mi-web.es

# Desde un fichero (una URL por línea; las líneas con # se ignoran)
header-auditor -f urls.txt

# Salida JSON
header-auditor example.com --json > informe.json

# En CI: termina con error si hay algún hallazgo de gravedad alta
header-auditor mi-web.es --fail-on high
```

También se puede ejecutar como módulo: `python -m header_auditor example.com`.

### Opciones

| Opción | Descripción |
|---|---|
| `-f, --file FICHERO` | Lee las URLs de un fichero |
| `--json` | Salida en formato JSON |
| `--fail-on {low,medium,high}` | Código de salida 1 si hay hallazgos de esa gravedad o mayor |
| `-t, --timeout SEG` | Tiempo de espera por petición (por defecto 10) |
| `-k, --insecure` | No verifica el certificado TLS |
| `-w, --workers N` | URLs auditadas en paralelo (por defecto 5) |
| `--no-color` | Desactiva los colores (también respeta la variable `NO_COLOR`) |

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Auditoría completada |
| `1` | Algún hallazgo alcanza el umbral de `--fail-on` |
| `2` | Argumentos incorrectos |
| `3` | Alguna URL no se pudo auditar (DNS, conexión, TLS, timeout) |

### Ejemplo en GitHub Actions

```yaml
- name: Auditar cabeceras de seguridad
  run: |
    pip install git+https://github.com/GuilletDominguez/header-auditor.git
    header-auditor https://mi-web.es --fail-on high
```

## Qué comprueba

| Cabecera | Qué protege | Qué se revisa | Gravedad si falta |
|---|---|---|---|
| HTTPS | Cifrado del tráfico | Que la respuesta final llegue por HTTPS | Alta |
| `Strict-Transport-Security` | SSL stripping | `max-age` ≥ 6 meses, `max-age=0`, `includeSubDomains` | Alta |
| `Content-Security-Policy` | XSS e inyección de contenido | `'unsafe-inline'` (sin nonce/hash), `'unsafe-eval'`, orígenes `*` `https:` `data:`, `object-src`, modo Report-Only | Alta |
| `X-Frame-Options` / `frame-ancestors` | Clickjacking | `DENY`/`SAMEORIGIN`, `ALLOW-FROM` obsoleto, o CSP `frame-ancestors` | Media |
| `X-Content-Type-Options` | MIME sniffing | Valor `nosniff` | Media |
| `Referrer-Policy` | Fuga de URLs a terceros | Políticas débiles (`unsafe-url`, `no-referrer-when-downgrade`) | Baja |
| `Permissions-Policy` | Acceso a APIs del navegador | Presencia | Baja |
| `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` | Aislamiento entre orígenes (Spectre, XS-Leaks) | Presencia | Info |
| `Access-Control-Allow-Origin` | Lectura de datos desde otros dominios | Origen reflejado, `null`, `*` con credenciales | — |
| `Set-Cookie` | Robo de sesión y CSRF | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` sin `Secure` | — |
| `Server`, `X-Powered-By`, `X-AspNet-Version` | Reconocimiento | Revelan tecnología o versión | — |
| `X-XSS-Protection`, `Public-Key-Pins`, `Expect-CT` | — | Cabeceras obsoletas | — |

## Cómo se calcula la nota

Se parte de 100 puntos y cada hallazgo resta según su gravedad:

| Gravedad | Penalización |
|---|---|
| Alta | −20 |
| Media | −10 |
| Baja | −5 |
| Info | 0 |

| Puntos | ≥ 95 | ≥ 85 | ≥ 70 | ≥ 55 | ≥ 40 | < 40 |
|---|---|---|---|---|---|---|
| Nota | A+ | A | B | C | D | F |

## Estructura del proyecto

```
src/header_auditor/
├── cli.py       # argumentos, ejecución en paralelo y códigos de salida
├── fetcher.py   # petición HTTP y normalización de URLs
├── checks.py    # comprobaciones (funciones puras registradas con @check)
├── scoring.py   # puntuación y nota
├── report.py    # salida en texto y JSON
└── models.py    # Severity, Finding, Target, ScanResult
```

Cada comprobación es una función pura que recibe la respuesta y devuelve una lista de hallazgos. Añadir una nueva es escribir una función con el decorador `@check`.

## Desarrollo

```bash
pip install -e ".[dev]"
pytest          # tests (no necesitan internet: la red se simula con mocks)
ruff check .    # linter
ruff format .   # formato
```

## Ideas futuras

- Informe en HTML.
- Comprobación de la configuración TLS (versiones y cifrados).
- Análisis de las cabeceras en cada redirección, no solo en la respuesta final.

## Uso responsable

La herramienta hace **una única petición GET** por URL, igual que un navegador. Úsala solo contra webs propias o sobre las que tengas permiso.

## Licencia

[MIT](LICENSE)
