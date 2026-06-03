[README_WebScanPro.md](https://github.com/user-attachments/files/28574189/README_WebScanPro.md)
```
  ╦ ╦╔═╗╔╗ ╔═╔═╗╔═╗╔╗╔  ╔═╗╦═╗╔═╗
  ║║║║╣ ╠╩╗╚═╗║  ╠═╣║║║  ╠═╝╠╦╝║ ║
  ╚╩╝╚═╝╚═╝╚═╝╚═╝╩ ╩╝╚╝  ╩  ╩╚═╚═╝
       Escáner de Vulnerabilidades Web v2.1
```

# WebScan Pro

**WebScan Pro** es un escáner de vulnerabilidades web ofensivo desarrollado en Bash. Cubre las principales categorías del OWASP Top 10 con detección automática, payloads multi-motor, análisis de cabeceras de seguridad, fingerprinting de tecnologías y generación de informes en tres formatos distintos — todo sin dependencias externas más allá de `curl` y `python3`.

> ⚠️ **USO EXCLUSIVO EN ENTORNOS AUTORIZADOS.** El uso de esta herramienta contra sistemas sin permiso explícito es ilegal. Diseñada para pentesters, bug hunters y equipos de seguridad.

---

## Características

- **11 módulos de detección** que cubren las categorías más críticas del OWASP Top 10
- **Sin dependencias externas** pesadas: solo `curl` y `python3`
- Detección de vulnerabilidades con **evidencias concretas** (URL, parámetro, payload, patrón)
- Sistema de **severidad** con cinco niveles: CRÍTICO / ALTO / MEDIO / BAJO / INFO
- **Score de riesgo global** calculado automáticamente al finalizar el escaneo
- **Módulo `--only`** para ejecutar un único módulo sin correr el escaneo completo
- **Timeout configurable** para adaptarse a entornos lentos o filtrados
- Generación automática de **tres tipos de informe** al finalizar:
  - `informe_ejecutivo.txt` — resumen para dirección/management
  - `informe_tecnico_IT.txt` — detalle técnico para el equipo IT
  - `informe_completo.html` — informe interactivo con filtros por severidad (abrir en navegador)

---

## Requisitos

- Linux / macOS con Bash
- `curl` (instalado por defecto en la mayoría de distros)
- `python3` (para URL encoding y generación de informes HTML)

---

## Instalación

```bash
git clone https://github.com/tuusuario/webscanpro.git
cd webscanpro
chmod +x webscanpro.sh
./webscanpro.sh -u https://objetivo.com
```

---

## Uso

```bash
./webscanpro.sh -u <URL> [opciones]
```

### Opciones

| Flag | Descripción |
|---|---|
| `-u, --url` | URL objetivo (obligatorio) |
| `-o, --output` | Directorio de salida (default: `~/Desktop/WebScan_<timestamp>`) |
| `-t, --timeout` | Timeout por petición en segundos (default: `12`) |
| `--only <módulo>` | Ejecutar solo un módulo (ver lista abajo) |
| `-h, --help` | Mostrar ayuda |

### Ejemplos

```bash
# Escaneo completo
./webscanpro.sh -u https://ejemplo.com

# Escaneo completo con timeout extendido y directorio personalizado
./webscanpro.sh -u https://ejemplo.com -t 20 -o /tmp/resultados

# Solo cabeceras de seguridad
./webscanpro.sh -u https://ejemplo.com --only headers

# Solo SQL Injection
./webscanpro.sh -u "https://ejemplo.com/buscar?q=test" --only sqli

# Solo detección de CMS
./webscanpro.sh -u https://ejemplo.com --only cms
```

---

## Módulos

### `headers` — Security Headers

Analiza las cabeceras HTTP de respuesta en busca de configuraciones de seguridad ausentes o inseguras:

| ID | Cabecera | Severidad |
|---|---|---|
| SH01 | Strict-Transport-Security (HSTS) ausente | ALTO |
| SH02 | Protección anti-Clickjacking ausente (X-Frame-Options / CSP frame-ancestors) | MEDIO |
| SH03 | X-Content-Type-Options ausente | BAJO |
| SH04 | Content-Security-Policy (CSP) ausente | MEDIO |
| SH05 | Referrer-Policy ausente | BAJO |
| SH06 | Permissions-Policy ausente | BAJO |
| SH07 | Divulgación de versión en cabecera Server | BAJO |
| SH08 | Divulgación de tecnología en X-Powered-By | BAJO |

---

### `sqli` — SQL Injection

Detecta inyecciones SQL en parámetros GET mediante tres estrategias:

- **Error-based**: inyecta payloads clásicos (`'`, `"`, `' OR 1=1--`, etc.) y detecta mensajes de error de MySQL, PostgreSQL, MSSQL, Oracle y SQLite en la respuesta
- **Parámetros existentes**: extrae y testea los parámetros de la URL proporcionada
- **Parámetros genéricos**: prueba con `?id=`, `?q=`, `?page=`, `?search=` si la URL no tiene parámetros
- **Blind time-based**: mide el tiempo de respuesta ante un payload `SLEEP(3)` para detectar SQLi ciego

**Severidad**: CRÍTICO (error-based) / ALTO (time-based)

---

### `xss` — Cross-Site Scripting

Detecta XSS reflejado en:

- Parámetros GET de la URL
- Formularios POST detectados automáticamente en el HTML de la página

Comprueba si el payload es devuelto sin codificar en la respuesta usando vectores habituales (`<script>`, `<img onerror>`, `<svg onload>`, `javascript:`, etc.).

**Severidad**: ALTO

---

### `xxe` — XML External Entity

Inyecta payloads XXE en endpoints que acepten XML o JSON. Incluye variantes para:

- Lectura de `/etc/passwd` y `/etc/hosts`
- OOB (Out-of-Band) con DTD externo
- Blind XXE vía error de parseo

Detecta endpoints XML buscando `Content-Type: application/xml` en respuestas y probando rutas comunes como `/api`, `/upload`, `/import`, `/soap`.

**Severidad**: CRÍTICO

---

### `lfi` — Local File Inclusion

Prueba path traversal y LFI clásico en parámetros comunes (`file`, `page`, `include`, `path`, `doc`, `view`, etc.) con payloads como:

- `../../../../etc/passwd`
- Variantes URL-encoded (`%2F`, `%252e`, `%2e%2e`)
- Null byte injection (`%00`)
- Wrappers PHP (`php://filter/convert.base64-encode/resource=`)
- Log poisoning vía User-Agent

**Severidad**: CRÍTICO

---

### `rfi` — Remote File Inclusion

Detecta inclusión de archivos remotos probando parámetros susceptibles con URLs que apuntan a recursos externos y al servicio de metadatos cloud (`169.254.169.254`). Una respuesta con contenido de metadatos AWS/GCP confirma RFI + SSRF simultáneo.

**Severidad**: CRÍTICO

---

### `path` — Path Traversal

Prueba traversal directo en la URL y en parámetros estáticos (`file`, `download`, `asset`, `img`, etc.) con payloads que incluyen variantes doble-encoded y separadores Windows (`%5C`). Confirma la vulnerabilidad verificando el contenido de `/etc/passwd` o `win.ini` en la respuesta.

**Severidad**: CRÍTICO

---

### `ssrf` — Server-Side Request Forgery

Prueba 17 parámetros comunes de redirección y proxy (`url`, `uri`, `redirect`, `callback`, `webhook`, `proxy`, `endpoint`, etc.) con payloads hacia:

- Servicio de metadatos cloud AWS/GCP (`169.254.169.254`)
- Loopback y localhost (`127.0.0.1`, `[::1]`, `0.0.0.0`, notaciones octales)
- Protocolos alternativos (`dict://`, `ftp://`)

**Severidad**: CRÍTICO (metadatos cloud) / ALTO (servicios internos)

---

### `ssti` — Server-Side Template Injection

El módulo más completo del escáner. Prueba expresiones matemáticas inequívocas (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`) en:

- Parámetros GET y POST (form-urlencoded y JSON)
- 25 parámetros comunes donde suele aparecer SSTI (`name`, `query`, `template`, `message`, `greeting`, etc.)
- Cabeceras HTTP (`User-Agent`, `Referer`, `X-Forwarded-For`)
- Segmentos de la ruta URL

Cubre los principales motores de plantillas:

| Motor | Lenguaje |
|---|---|
| Jinja2 | Python (Flask, Django) |
| Twig | PHP (Symfony, Laravel) |
| FreeMarker | Java |
| Velocity | Java |
| Smarty | PHP |
| ERB / Mako | Ruby / Python |
| Handlebars / Nunjucks / Pug | Node.js |
| Pebble | Java |

Incluye heurística basada en cabeceras HTTP para sugerir el motor probable cuando no se confirma SSTI automáticamente.

**Severidad**: CRÍTICO

---

### `cms` — CMS Detection

Detecta CMS y tecnologías web, con checks adicionales de seguridad específicos para cada uno:

| CMS / Tecnología | Checks adicionales |
|---|---|
| WordPress | Versión expuesta, xmlrpc.php, readme.html, wp-admin accesible |
| Joomla! | Detección de indicadores en código |
| Drupal | Detección de indicadores en cabeceras y cuerpo |
| phpMyAdmin | Acceso público (CRÍTICO) |

**Severidad**: INFO a CRÍTICO (según el hallazgo específico)

---

### `files` — Sensitive Files

Comprueba la accesibilidad de archivos y rutas sensibles habituales:

- Archivos de configuración: `.env`, `config.php`, `database.yml`, `settings.py`, `web.config`, `appsettings.json`
- Archivos de backup: `backup.zip`, `db.sql`, `dump.sql`, `*.bak`
- Paneles de administración: `/admin`, `/administrator`, `/panel`, `/dashboard`, `/cpanel`
- Archivos de desarrollo: `.git/config`, `.svn/entries`, `Dockerfile`, `docker-compose.yml`, `package.json`
- Logs: `error.log`, `access.log`, `debug.log`, `laravel.log`

**Severidad**: CRÍTICO a BAJO (según la exposición)

---

## Informes generados

Al finalizar el escaneo se generan automáticamente tres informes en el directorio de salida:

### `informe_ejecutivo.txt`
Resumen no técnico orientado a management. Incluye el nivel de riesgo global, conteo de vulnerabilidades por severidad y las recomendaciones principales.

### `informe_tecnico_IT.txt`
Detalle técnico para el equipo de desarrollo y seguridad. Incluye cada hallazgo con su evidencia exacta (URL, parámetro, payload), descripción del impacto y pasos de remediación.

### `informe_completo.html`
Informe interactivo con tema oscuro. Funcionalidades:
- Filtros por severidad (CRÍTICO / ALTO / MEDIO / BAJO / INFO)
- Cards expandibles por hallazgo
- Tabla resumen con todos los findings
- Plan de remediación
- Checklist post-remediación
- Barras de progreso animadas por categoría

---

## Estructura de salida

```
~/Desktop/WebScan_20241215_143022/
├── informe_ejecutivo.txt
├── informe_tecnico_IT.txt
└── informe_completo.html
```

---

## Sistema de severidad y score de riesgo

| Severidad | Peso | Descripción |
|---|---|---|
| CRÍTICO | ×10 | Explotación directa, impacto máximo (RCE, SQLi, SSRF a metadatos) |
| ALTO | ×5 | Impacto alto con condiciones (XSS, SSRF interno, xmlrpc) |
| MEDIO | ×3 | Configuraciones inseguras explotables con contexto (CSP ausente, Clickjacking) |
| BAJO | ×1 | Información expuesta, cabeceras informativas |
| INFO | ×0 | Detecciones informativas (CMS identificado) |

El **score de riesgo global** se calcula como `(CRÍTICOS×10) + (ALTOS×5) + (MEDIOS×3) + (BAJOS×1)` y se clasifica en: BAJO (<5) / MEDIO (≥5) / ALTO (≥10) / CRÍTICO (≥20).

---

## Disclaimer

Esta herramienta realiza pruebas pasivas y semi-activas. Los resultados son orientativos y deben complementarse con análisis manual.

**Úsala exclusivamente en sistemas sobre los que tengas autorización explícita por escrito. El autor no se hace responsable del uso indebido.**

---

## Licencia

MIT License — libre para usar, modificar y distribuir con atribución.
