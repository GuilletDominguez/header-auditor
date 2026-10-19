# header-auditor

Herramienta de línea de comandos en Python que audita las cabeceras de seguridad HTTP de una web y da recomendaciones para mejorarlas.

> 🚧 En desarrollo.

## Objetivo

- Comprobar si faltan las cabeceras de seguridad más importantes (HSTS, CSP, X-Frame-Options…).
- Analizar sus valores para detectar configuraciones débiles, no solo si la cabecera existe.
- Dar una nota global y recomendaciones concretas.

## Uso responsable

La herramienta hace una única petición GET, igual que un navegador. Úsala solo contra webs propias o sobre las que tengas permiso.

## Licencia

[MIT](LICENSE)
