
                                                                          
              W E B S C A N   P R O   v 2 . 0                             
          Manual de Usuario y Referencia Tecnica                          
                                                                          
   Escaner de Vulnerabilidades Web — Script Bash autonomo                  
   Cubre: SQLi · XSS · XXE · LFI · RFI · Path Traversal                  
          SSRF · SSTI · CMS Detection · Security Headers                  
                                                                        

 
  Clasificacion : USO INTERNO / CONFIDENCIAL
  Version       : 2.0
  Fecha manual  : Marzo 2026
  Dependencias  : Bash 4+  |  Python 3.6+  |  curl
 

  INDICE

 
  1.  Descripcion general
  2.  Requisitos del sistema
  3.  Instalacion y primeros pasos
  4.  Sintaxis y opciones de uso
  5.  Modulos de deteccion (12 modulos)
       5.01  Security Headers
       5.02  SQL Injection (SQLi)
       5.03  Cross-Site Scripting (XSS)
       5.04  XML External Entity (XXE)
       5.05  Local File Inclusion (LFI)
       5.06  Remote File Inclusion (RFI)
       5.07  Path Traversal
       5.08  Server-Side Request Forgery (SSRF)
       5.09  Server-Side Template Injection (SSTI)
       5.10  Deteccion de CMS y tecnologias
       5.11  Archivos y rutas sensibles
       5.12  Fingerprinting y configuracion general
  6.  Sistema de niveles de criticidad
  7.  Informes generados
       7.1   Informe ejecutivo (.txt)
       7.2   Informe tecnico IT (.txt)
       7.3   Informe completo (.html)
  8.  Interpretacion de resultados
  9.  Ejemplos de uso practicos
  10. Preguntas frecuentes (FAQ)
  11. Limitaciones conocidas
  12. Aviso legal
 
 

  1. DESCRIPCION GENERAL
 
WebScan Pro es una herramienta de analisis de seguridad web implementada como un
unico script Bash autonomo. Combina logica de deteccion propia en Bash con un
generador de informes embebido en Python que se ejecuta automaticamente al
finalizar cada escaneo.
 
La herramienta evalua los vectores de ataque mas frecuentes definidos por OWASP
Top 10 y genera de forma automatica tres documentos de resultados listos para
entregar: un informe ejecutivo orientado a direccion, un informe tecnico para el
equipo IT y un informe HTML interactivo con filtros por severidad.
 
Caracteristicas principales:
 
  - Script unico, sin instalacion. Solo necesita curl y Python 3.
  - 12 modulos de deteccion independientes y ejecutables por separado.
  - Pruebas en GET, POST form-urlencoded, POST JSON y cabeceras HTTP.
  - Sistema de puntuacion de riesgo global (0-100).
  - Generacion automatica de 3 informes al finalizar cada escaneo.
  - Los informes se guardan en una carpeta con marca de tiempo en ~/Desktop.
  - Timeout configurable para adaptarse a redes lentas.
 
 
  2. REQUISITOS DEL SISTEMA
 
  Obligatorios:
  
   Componente:        Version mínima:            Verificación:                
  
   Bash              4.0 o superior              bash --version               
   Python            3.6 o superior              python3 --version            
   curl              Cualquier version moderna   curl --version               

 
  Sistemas operativos compatibles:
    - GNU/Linux (Debian, Ubuntu, Kali, Parrot, Arch, CentOS, Fedora...)
    - macOS 10.15 o superior (con Bash 4+ instalado via Homebrew)
    - Windows 10/11 mediante WSL2 (Windows Subsystem for Linux)
 
  Nota sobre macOS: El Bash incluido en macOS es la version 3.x por motivos de
  licencia. Se debe instalar Bash 4+ con: brew install bash
 
  Nota sobre WSL: En Windows con WSL2 la carpeta ~/Desktop puede no existir.
  Usar la opcion -o para especificar un directorio de salida alternativo.
  Ejemplo: ./webscan.sh -u https://objetivo.com -o /mnt/c/Users/TuUsuario/Desktop
 
 

  3. INSTALACION Y PRIMEROS PASOS
 
  Paso 1: Descargar o copiar el fichero webscan.sh en tu sistema.
 
  Paso 2: Dar permisos de ejecucion:
 
    chmod +x webscan.sh
 
  Paso 3: Verificar que los requisitos estan disponibles:
 
    bash --version     # Debe ser >= 4.0
    python3 --version  # Debe ser >= 3.6
    curl --version     # Cualquier version
 
  Paso 4: Ejecutar el primer escaneo:
 
    ./webscan.sh -u https://tu-objetivo.com
 
  El script creara automaticamente una carpeta en ~/Desktop con el nombre:
 
    WebScan_YYYYMMDD_HHMMSS/
 
  Dentro de esa carpeta encontraras los tres informes al finalizar el escaneo.
 
  Ubicacion alternativa si no existe ~/Desktop:
 
    ./webscan.sh -u https://objetivo.com -o ~/informes/escaneo1
 
 

  4. SINTAXIS Y OPCIONES DE USO
 
  Uso basico:
    ./webscan.sh -u <URL> [opciones]
 
  Opciones disponibles:
  
   Opcion         Descripcion                                               
 
   -u, --url      URL objetivo (OBLIGATORIO). Incluye http:// o https://     
                   Si se omite el protocolo, se asume http://                 

   -o, --output   Directorio de salida para los informes                     
                  Por defecto: ~/Desktop/WebScan_<timestamp>                 

   -t, --timeout  Segundos de espera maxima por peticion HTTP                
                  Por defecto: 12 segundos. Aumentar en redes lentas.        

   --only <mod>   Ejecutar un unico modulo. Ver lista de modulos abajo.      
                  Util para escaneos rapidos o dirigidos.                    
  
   -h, --help     Mostrar ayuda rapida en pantalla.                          
  
 
  Valores validos para --only:
    headers   Cabeceras de seguridad HTTP
    sqli      SQL Injection
    xss       Cross-Site Scripting
    xxe       XML External Entity
    lfi       Local File Inclusion
    rfi       Remote File Inclusion
    path      Path / Directory Traversal
    ssrf      Server-Side Request Forgery
    ssti      Server-Side Template Injection
    cms       Deteccion de CMS y tecnologias
    files     Archivos y rutas sensibles
 
  Ejemplos rapidos:
    ./webscan.sh -u https://ejemplo.com
    ./webscan.sh -u https://ejemplo.com --only headers
    ./webscan.sh -u https://ejemplo.com -o /tmp/resultados -t 20
    ./webscan.sh -u http://192.168.1.50:8080 --only sqli
 
 

  5. MODULOS DE DETECCION

 
  La herramienta ejecuta 12 modulos de forma secuencial. Cada modulo es
  independiente y puede lanzarse de forma aislada con --only.
 
  A continuacion se describe en detalle que comprueba cada modulo, como lo
  hace y que tipo de hallazgos puede generar.
 

  5.01  SECURITY HEADERS (cabeceras de seguridad HTTP)
  
 
  Que comprueba:
    Analiza las cabeceras de respuesta HTTP del servidor para detectar la
    ausencia de cabeceras de seguridad recomendadas por OWASP y los
    organismos de estandarizacion web.
 
  Como funciona:
    Realiza una peticion HEAD al objetivo y examina las cabeceras recibidas.
 
  Hallazgos posibles:

   ID      Descripcion                                         Severidad   
 
   SH01    Falta Strict-Transport-Security (HSTS)               ALTO        
   SH02    Falta proteccion anti-Clickjacking                   MEDIO
          (X-Frame-Options o CSP frame-ancestors)                         
   SH03    Falta X-Content-Type-Options                         BAJO        
   SH04    Falta Content-Security-Policy (CSP)                  MEDIO       
   SH05    Falta Referrer-Policy                                BAJO        
   SH06    Falta Permissions-Policy                             BAJO        
   SH07    Cabecera Server revela version del servidor          BAJO        
   SH08    Cabecera X-Powered-By revela tecnologia              BAJO        

 
 
  5.02  SQL INJECTION (SQLi)

 
  Que comprueba:
    Intenta provocar errores SQL o retrasos de tiempo para detectar si los
    parametros de la aplicacion son vulnerables a inyeccion SQL.
 
  Como funciona:
    - Error-based: inyecta comillas simples y dobles, clausulas OR y
      sentencias DROP en parametros URL existentes y en parametros genericos
      (id, q, page, search). Busca mensajes de error SQL en la respuesta.
    - Time-based blind: inyecta SLEEP(3) y WAITFOR DELAY '0:0:3'. Mide el
      tiempo de respuesta. Si supera 2.8 segundos, notifica posible SQLi ciego.
 
  Payloads utilizados:
    '   "   ' OR '1'='1   ' OR 1=1--   1; DROP TABLE users--
    ' AND SLEEP(3)--   1' WAITFOR DELAY '0:0:3'--
 
  Patrones de error buscados en la respuesta:
    SQL syntax, mysql_fetch, ORA-XXXX, Microsoft OLE DB, PostgreSQL ERROR,
    Warning mysql_, sqlite3.OperationalError, PG::SyntaxError, entre otros.
 
  Hallazgos posibles:
  
   ID      Descripcion                                         Severidad   

   SQLI01  SQL Injection Error-Based confirmado                CRITICO     
   SQLI02  SQL Injection Blind Time-Based sospechoso           ALTO        
 
 

  5.03  CROSS-SITE SCRIPTING (XSS)

 
  Que comprueba:
    Verifica si la aplicacion refleja el input del usuario sin codificar,
    lo que permitiria ejecutar JavaScript arbitrario en el navegador de
    otra persona.
 
  Como funciona:
    - Reflected XSS GET: inyecta payloads en parametros URL. Comprueba si
      el payload aparece literalmente sin codificar en la respuesta HTML.
    - Reflected XSS POST: detecta formularios HTML en la pagina y envia
      el payload por POST. Verifica si se refleja en la respuesta.
    - JSON: envia payloads en cuerpos JSON a endpoints detectados.
 
  Payloads utilizados:
    <script>alert(1)</script>
    <img src=x onerror=alert(1)>
    '"><script>alert(1)</script>
    <svg onload=alert(1)>
    javascript:alert(1)
    <body onload=alert(1)>
    "onmouseover="alert(1)
 
  Hallazgos posibles:
 
   ID      Descripcion                                         Severidad   
 
   XSS01   XSS Reflejado en parametro GET                      ALTO        
   XSS02   XSS en formulario POST                              ALTO        

 
  
  5.04  XML EXTERNAL ENTITY (XXE)

 
  Que comprueba:
    Detecta si el servidor procesa entidades XML externas, lo que permite
    leer ficheros del sistema, realizar SSRF interno o provocar denegacion
    de servicio.
 
  Como funciona:
    Envia peticiones POST con cuerpos XML maliciosos a endpoints comunes
    (/api, /upload, /xml, /ws, /service, /soap, /api/v1). Busca contenido
    de /etc/passwd en la respuesta o mensajes de error del parser XML.
    Tambien detecta si el Content-Type de la respuesta principal es XML.
 
  Payloads utilizados:
    DTD con entidad SYSTEM apuntando a file:///etc/passwd
    DTD con entidad SYSTEM apuntando al servicio de metadatos cloud
    DTD con entidad parametro para XXE out-of-band
 
  Hallazgos posibles:
 
   ID      Descripcion                                        Severidad   
  
   XXE01   XXE confirmado — lectura de /etc/passwd             CRITICO     
   XXE02   Parser XML expuesto con errores visibles            ALTO        
   XXE03   Endpoint devuelve XML — revisar manualmente         MEDIO       
 
 

  5.05  LOCAL FILE INCLUSION (LFI)
 
  Que comprueba:
    Verifica si parametros que reciben nombres de fichero o rutas pueden
    manipularse para leer ficheros arbitrarios del servidor.
 
  Como funciona:
    Prueba una lista de 15 parametros tipicamente vulnerables (file, page,
    include, path, doc, template, view, etc.) con 11 payloads de traversal.
    Busca el contenido de /etc/passwd o win.ini en la respuesta.
    Adicionalmente prueba wrappers PHP (php://filter) para leer codigo
    fuente codificado en base64.
 
  Parametros testeados:
    file, page, include, path, doc, document, filename, filepath,
    template, view, load, read, dir, pg, p
 
  Payloads de traversal:
    ../../../etc/passwd             ....//....//etc/passwd
    ../../../../etc/passwd          php://filter/convert.base64-encode/...
    ../../../../../etc/passwd       php://filter/read=string.rot13/...
    ..%2F..%2F..%2Fetc%2Fpasswd    ../../../windows/win.ini
    /etc/passwd (ruta absoluta)
 
  Hallazgos posibles:

   ID      Descripcion                                         Severidad   
  
   LFI01   LFI confirmado — fichero del sistema leido          CRITICO     
   LFI02   LFI con PHP Wrapper base64 confirmado               CRITICO     
  

  5.06  REMOTE FILE INCLUSION (RFI)
 
 
  Que comprueba:
    Detecta si los parametros de la aplicacion pueden cargarse URLs
    remotas, lo que permitiria ejecutar codigo PHP alojado en un servidor
    externo controlado por el atacante.
 
  Como funciona:
    Prueba 9 parametros tipicos (url, uri, src, href, path, url, src,
    template, load) con URLs de prueba incluyendo el servicio de metadatos
    cloud de AWS (169.254.169.254) y google.com. Detecta si la respuesta
    contiene contenido de esas URLs.
 
  Payloads utilizados:
    http://169.254.169.254/latest/meta-data/
    https://www.google.com/
    http://evil.example.com/shell.php
    ftp://evil.example.com/shell.php
    \\attacker.com\share\shell.php
 
  Hallazgos posibles:
  +--------+----------------------------------------------------+-------------+
  | ID     | Descripcion                                        | Severidad   |
  +--------+----------------------------------------------------+-------------+
  | RFI01  | RFI + SSRF a metadatos cloud confirmado            | CRITICO     |
  | RFI02  | RFI — carga de URL remota confirmada               | CRITICO     |
  +--------+----------------------------------------------------+-------------+
 
  ____________________________________________________________________________
  5.07  PATH TRAVERSAL (Directory Traversal)
  ____________________________________________________________________________
 
  Que comprueba:
    Detecta si es posible acceder a ficheros fuera del directorio raiz web
    manipulando la ruta en la URL o en parametros de fichero.
 
  Como funciona:
    Prueba 7 variantes de traversal directamente en el path de la URL y
    adicionalmente en 9 parametros estaticos tipicos (file, doc, download,
    asset, static, img, image, f, filename). Busca contenido de /etc/passwd
    o win.ini en la respuesta. Incluye variantes con encoding URL simple,
    doble encoding y separadores Windows.
 
  Payloads de path:
    /../../../etc/passwd            /..%2F..%2F..%2Fetc%2Fpasswd
    /....//....//etc/passwd        /%2e%2e/%2e%2e/etc/passwd
    /%252e%252e/%252e%252e/...     /../../../windows/win.ini
    /..%5c..%5c..%5cwindows%5c...
 
  Hallazgos posibles:
  +--------+----------------------------------------------------+-------------+
  | ID     | Descripcion                                        | Severidad   |
  +--------+----------------------------------------------------+-------------+
  | PT01   | Path Traversal en URL confirmado                   | CRITICO     |
  | PT02   | Path Traversal en parametro confirmado             | CRITICO     |
  +--------+----------------------------------------------------+-------------+
 
  ____________________________________________________________________________
  5.08  SERVER-SIDE REQUEST FORGERY (SSRF)
  ____________________________________________________________________________
 
  Que comprueba:
    Detecta si la aplicacion realiza peticiones HTTP del lado del servidor
    a URLs controladas por el usuario, lo que puede usarse para acceder a
    servicios internos o metadatos de infraestructura cloud.
 
  Como funciona:
    Prueba 17 parametros tipicos (url, uri, src, href, dest, redirect,
    proxy, callback, endpoint, webhook, fetch, etc.) con 10 payloads
    que apuntan a direcciones de loopback y al endpoint de metadatos cloud
    de AWS/GCP. Busca en la respuesta indicadores de acceso exitoso.
 
  Parametros testeados:
    url, uri, src, href, path, dest, redirect, out, target, proxy,
    callback, endpoint, webhook, next, continue, data, fetch
 
  Payloads utilizados:
    http://169.254.169.254/latest/meta-data/
    http://169.254.169.254/latest/meta-data/iam/security-credentials/
    http://[::1]/       http://localhost/       http://127.0.0.1/
    http://0.0.0.0/     http://2130706433/      http://017700000001/
    dict://localhost:6379/     ftp://localhost/
 
  Hallazgos posibles:
  +--------+----------------------------------------------------+-------------+
  | ID     | Descripcion                                        | Severidad   |
  +--------+----------------------------------------------------+-------------+
  | SSRF01 | SSRF — acceso a metadatos cloud confirmado         | CRITICO     |
  | SSRF02 | SSRF — acceso a servicios internos detectado       | ALTO        |
  +--------+----------------------------------------------------+-------------+
 
  ____________________________________________________________________________
  5.09  SERVER-SIDE TEMPLATE INJECTION (SSTI)
  ____________________________________________________________________________
 
  Que comprueba:
    Detecta si el input del usuario es procesado directamente por un motor
    de plantillas del servidor, lo que permite ejecutar codigo arbitrario
    en el servidor (equivalente a RCE).
 
  Como funciona:
    Utiliza sondas matematicas inequivocas: si {{7*7}} devuelve 49 en la
    respuesta, hay evaluacion de expresiones. Cubre 10 motores de
    plantillas diferentes usando sus sintaxis especificas.
 
    Vectores de inyeccion probados:
      - Parametros GET (26 parametros: name, q, search, template, view,
        msg, message, title, content, username, email, greeting, etc.)
      - Parametros POST form-urlencoded
      - Cuerpos JSON (Content-Type: application/json)
      - Cabeceras HTTP (User-Agent, Referer, X-Forwarded-For, etc.)
      - Segmentos de ruta URL (/{{7*7}}, /${7*7}, etc.)
 
    Motores cubiertos y sus payloads de deteccion:
    +-------------------------+-------------------------------------+-----------+
    | Motor / Tecnologia      | Payload                             | Resultado |
    +-------------------------+-------------------------------------+-----------+
    | Jinja2 (Python/Flask)   | {{7*7}}                             | 49        |
    | Jinja2 confirmacion     | {{7*'7'}}                           | 7777777   |
    | Twig (PHP/Symfony)      | {{7*7}}                             | 49        |
    | FreeMarker (Java)       | ${7*7}                              | 49        |
    | FreeMarker string       | ${'freemarker'.toUpperCase()}       | FREEMARKER|
    | Thymeleaf (Java/Spring) | ${7*7}                              | 49        |
    | Velocity (Java)         | #set($x=7*7)${x}                    | 49        |
    | Smarty (PHP)            | {math equation='7*7'}               | 49        |
    | ERB (Ruby/Rails)        | <%= 7*7 %>                          | 49        |
    | Mako (Python)           | ${7*7}                              | 49        |
    | Nunjucks (Node.js)      | {{range.constructor('return 7*7')}} | 49        |
    | Handlebars (Node.js)    | {{this.constructor}}                | function  |
    | Pebble (Java)           | {{7*7}}                             | 49        |
    +-------------------------+-------------------------------------+-----------+
 
    Heuristica de tecnologia: si no se confirma inyeccion activa pero las
    cabeceras del servidor revelan Flask, Django, Laravel, Symfony, Spring,
    Rails, Handlebars o Nunjucks, emite un hallazgo MEDIO recomendando
    revision manual en profundidad.
 
  Hallazgos posibles:
  +--------+----------------------------------------------------+-------------+
  | ID     | Descripcion                                        | Severidad   |
  +--------+----------------------------------------------------+-------------+
  | SSTI01 | SSTI confirmado en parametro (GET/POST/JSON)       | CRITICO     |
  | SSTI02 | SSTI en cabecera HTTP                              | CRITICO     |
  | SSTI03 | SSTI en segmento de ruta URL                       | CRITICO     |
  | SSTI04 | Tecnologia de plantillas detectada — revisar       | MEDIO       |
  +--------+----------------------------------------------------+-------------+
 
  ____________________________________________________________________________
  5.10  DETECCION DE CMS Y TECNOLOGIAS
  ____________________________________________________________________________
 
  Que comprueba:
    Identifica el CMS (Sistema de Gestion de Contenidos) y las tecnologias
    del servidor. Ademas verifica configuraciones por defecto inseguras de
    los CMS detectados.
 
  Como funciona:
    Analiza el cuerpo de la pagina principal y las cabeceras HTTP buscando
    huellas digitales de los CMS mas comunes. Para WordPress, ademas prueba
    rutas especificas conocidas por ser vectores de ataque habituales.
 
  CMS y tecnologias detectados:
    - WordPress: detecta wp-content/, wp-includes/, meta generator, version
      expuesta, xmlrpc.php accesible, readme.html accesible.
    - Joomla!: detecta mosConfig, /components/com_
    - Drupal: detecta referencias a Drupal en body y cabeceras.
    - phpMyAdmin: comprueba si /phpmyadmin es accesible (HTTP 200).
    - Tecnologias: PHP, ASP.NET, Ruby/Rails, Python/Django/Flask,
      Node.js/Express, Java/Tomcat.
 
  Adicionalmente comprueba:
    - robots.txt: si existe y contiene rutas en Disallow que puedan
      revelar directorios sensibles.
 
  Hallazgos posibles:
  +--------+----------------------------------------------------+-------------+
  | ID     | Descripcion                                        | Severidad   |
  +--------+----------------------------------------------------+-------------+
  | CMS01  | WordPress detectado                                | INFO        |
  | CMS02  | Version de WordPress expuesta                      | BAJO        |
  | CMS03  | WordPress xmlrpc.php accesible                     | ALTO        |
  | CMS04  | WordPress readme.html accesible                    | BAJO        |
  | CMS10  | Joomla! detectado                                  | INFO        |
  | CMS11  | Drupal detectado                                   | INFO        |
  | CMS20  | phpMyAdmin expuesto publicamente                   | CRITICO     |
  | CMS30  | Tecnologias del servidor detectadas                | INFO        |
  | CMS31  | Directorios sensibles en robots.txt                | BAJO        |
  +--------+----------------------------------------------------+-------------+
 
  ____________________________________________________________________________
  5.11  ARCHIVOS Y RUTAS SENSIBLES
  ____________________________________________________________________________
 
  Que comprueba:
    Verifica si hay ficheros o directorios sensibles accesibles publicamente
    que no deberian estar expuestos en un entorno de produccion.
 
  Como funciona:
    Realiza peticiones GET a una lista de 30 rutas conocidas. Si recibe
    HTTP 200, 301 o 302 notifica el hallazgo con la severidad apropiada
    segun el tipo de fichero.
 
  Rutas comprobadas:
    /.git/HEAD          /.git/config       /.env          /.env.local
    /.env.production    /config.php        /wp-config.php /configuration.php
    /config/database.yml                   /admin         /administrator
    /admin.php          /admin/login       /backup        /backup.zip
    /backup.tar.gz      /db.sql            /database.sql  /phpinfo.php
    /info.php           /test.php          /debug.php     /.htaccess
    /web.config         /server-status     /server-info   /api/v1/users
    /api/users          /api/admin         /actuator      /actuator/env
    /actuator/mappings  /console           /h2-console    /_profiler
 
  Hallazgos posibles (severidad segun tipo de fichero):
    CRITICO : /.git/, /.env, backups (*.zip, *.sql, *.tar.gz), /wp-config.php
    ALTO    : /phpinfo.php, /info.php, /actuator/env
    MEDIO   : /admin, /administrator, /server-status, y otros
 
  ____________________________________________________________________________
  5.12  FINGERPRINTING Y CONFIGURACION GENERAL
  ____________________________________________________________________________
 
  Que comprueba:
    Verifica configuraciones generales del servidor y de la aplicacion que
    no encajan en los modulos anteriores pero impactan en la seguridad.
 
  Comprobaciones realizadas:
 
    Cookies sin flags de seguridad:
      - Detecta cookies sin HttpOnly (robables mediante XSS).
      - Detecta cookies sin Secure (transmisibles en texto claro).
      - Detecta cookies sin SameSite (vulnerables a CSRF).
 
    HTTPS:
      - Si el objetivo es HTTP, comprueba si existe version HTTPS y si
        hay redireccion automatica de HTTP a HTTPS.
 
    Directory Listing:
      - Comprueba 8 directorios tipicos (/images/, /uploads/, /files/,
        /backup/, /assets/, /static/, /media/, /docs/) para detectar
        si el servidor muestra el listado de ficheros.
 
    Metodos HTTP peligrosos:
      - Envia una peticion OPTIONS y examina la cabecera Allow.
        Notifica si estan habilitados TRACE, DELETE, PUT o CONNECT.
 
  Hallazgos posibles:
  +--------+----------------------------------------------------+-------------+
  | ID     | Descripcion                                        | Severidad   |
  +--------+----------------------------------------------------+-------------+
  | FP01   | Cookies sin flag HttpOnly                          | ALTO        |
  | FP02   | Cookies sin flag Secure                            | MEDIO       |
  | FP03   | Cookies sin atributo SameSite                      | BAJO        |
  | FP04   | HTTP no redirige a HTTPS automaticamente            | MEDIO       |
  | FP05   | Directory Listing habilitado                        | MEDIO       |
  | FP06   | Metodos HTTP peligrosos habilitados                 | MEDIO       |
  +--------+----------------------------------------------------+-------------+
 
 
================================================================================
  6. SISTEMA DE NIVELES DE CRITICIDAD
================================================================================
 
  Cada hallazgo se clasifica en uno de los siguientes cinco niveles:
 
  +-------------+--------+------------------------------------------------------+
  | Nivel       | Puntos | Impacto potencial                                    |
  +-------------+--------+------------------------------------------------------+
  | [!!!]       |   +10  | Compromiso total del sistema. Explotacion inmediata  |
  | CRITICO     |        | posible: RCE, extraccion de BBDD, robo de credenciales|
  +-------------+--------+------------------------------------------------------+
  | [!! ]       |    +5  | Exposicion de datos sensibles o acceso no autorizado |
  | ALTO        |        | a funcionalidades criticas.                          |
  +-------------+--------+------------------------------------------------------+
  | [!  ]       |    +3  | Degradacion del servicio, fuga de informacion o      |
  | MEDIO       |        | posibilidad de ataques mas complejos.                |
  +-------------+--------+------------------------------------------------------+
  | [.  ]       |    +1  | Riesgo menor. No explotable directamente pero mejora |
  | BAJO        |        | la superficie de ataque.                             |
  +-------------+--------+------------------------------------------------------+
  | [i  ]       |     0  | Informacion relevante sin impacto de seguridad       |
  | INFO        |        | directo. Tecnologias detectadas, configuraciones, etc|
  +-------------+--------+------------------------------------------------------+
 
  Puntuacion de riesgo global:
 
    Score = (CRITICOS x 10) + (ALTOS x 5) + (MEDIOS x 3) + (BAJOS x 1)
 
    +----------------+----------------------------------------------------------+
    | Score          | Nivel de riesgo global                                   |
    +----------------+----------------------------------------------------------+
    | 0 - 4          | BAJO — Postura de seguridad aceptable                    |
    | 5 - 9          | MEDIO — Requiere mejoras planificadas                    |
    | 10 - 19        | ALTO — Requiere accion urgente                           |
    | 20 o mas       | CRITICO — Requiere accion inmediata                      |
    +----------------+----------------------------------------------------------+
 
  Ejemplo:
    2 hallazgos CRITICOS, 1 ALTO y 3 MEDIOS:
    Score = (2x10) + (1x5) + (3x3) = 20 + 5 + 9 = 34 → Nivel: CRITICO
 
 
================================================================================
  7. INFORMES GENERADOS
================================================================================
 
  Al finalizar el escaneo (o al usar --only) el script genera automaticamente
  tres ficheros en el directorio de salida configurado.
 
  ____________________________________________________________________________
  7.1  INFORME EJECUTIVO  (informe_ejecutivo.txt)
  ____________________________________________________________________________
 
  Destinatario: Direccion, gerencia, responsables de negocio.
 
  Contenido:
    1. Cabecera con datos del escaneo y nivel de riesgo global.
    2. Resumen ejecutivo en lenguaje no tecnico.
    3. Tabla de KPIs con conteo por severidad y accion requerida.
    4. Listado de hallazgos criticos y altos con descripcion simplificada.
    5. Las 8 recomendaciones prioritarias ordenadas por urgencia.
    6. Conclusion y propuesta de proximos pasos.
 
  Formato: texto plano, 76 caracteres de ancho, compatible con cualquier
  editor o cliente de correo. Sin caracteres especiales ni Unicode.
 
  ____________________________________________________________________________
  7.2  INFORME TECNICO IT  (informe_tecnico_IT.txt)
  ____________________________________________________________________________
 
  Destinatario: Equipo de desarrollo, administradores de sistemas, DevOps.
 
  Contenido:
    1. Cabecera tecnica con todos los metadatos del escaneo.
    2. Descripcion de la metodologia y alcance del analisis.
    3. Tabla estadistica con porcentajes y puntuacion por severidad.
    4. Bloque detallado por cada hallazgo:
       - Severidad, ID y categoria
       - Descripcion tecnica del problema
       - Evidencia exacta (URL, parametro, payload, patron detectado)
       - Recomendacion tecnica de remediacion
    5. Plan de remediacion priorizado en tres niveles.
    6. Checklist de verificacion post-remediacion (17 puntos).
 
  Formato: texto plano, 78 caracteres de ancho, con marcos ASCII para
  facilitar la lectura. Compatible con cualquier editor de texto.
 
  ____________________________________________________________________________
  7.3  INFORME COMPLETO HTML  (informe_completo.html)
  ____________________________________________________________________________
 
  Destinatario: Cualquier persona. Se puede compartir y abrir en navegador.
 
  Contenido:
    - Cabecera visual con datos del objetivo y nivel de riesgo codificado
      por color.
    - Navegacion fija con acceso rapido a cada seccion.
    - Panel de estadisticas con contadores por severidad.
    - Grafico de barras animado.
    - Listado interactivo de hallazgos: clic para expandir/contraer cada
      tarjeta. Cada tarjeta muestra descripcion, evidencia y recomendacion.
    - Botones de filtrado por nivel de severidad (Todos, Critico, Alto...).
    - Tabla resumen con todos los hallazgos.
    - Seccion de plan de remediacion solo para hallazgos urgentes.
    - Checklist interactivo con casillas marcables.
 
  Como abrir:
    Doble clic en el fichero .html o desde la terminal:
      firefox informe_completo.html
      google-chrome informe_completo.html
      xdg-open informe_completo.html   (Linux, abre el navegador por defecto)
      open informe_completo.html        (macOS)
 
 
================================================================================
  8. INTERPRETACION DE RESULTADOS
================================================================================
 
  Durante el escaneo, cada hallazgo se muestra en pantalla con el
  siguiente formato:
 
    [SEVERIDAD] Nombre del hallazgo
    |-- Categoria:      Categoria OWASP o tecnica
    |-- Descripcion:    Explicacion del problema en terminos sencillos
    |-- Evidencia:      URL, parametro o patron exacto que confirma el hallazgo
    +-- Recomendacion:  Accion tecnica concreta para corregirlo
 
  Al final del escaneo se muestra el resumen con el recuento por severidad
  y el nivel de riesgo global calculado.
 
  Guia para priorizar:
 
    CRITICO: Detener el servicio si esta en produccion. Corregir de
             inmediato antes de cualquier reexposicion publica.
 
    ALTO:    Planificar correccion en menos de 72 horas. No desplegar
             nueva version sin haberlo corregido.
 
    MEDIO:   Incluir en el proximo sprint o ciclo de desarrollo.
             No supone riesgo inmediato pero debe corregirse.
 
    BAJO:    Backlog de seguridad. Mejorar cuando sea posible.
 
    INFO:    No requiere accion. Util para el contexto del informe.
 
 
================================================================================
  9. EJEMPLOS DE USO PRACTICOS
================================================================================
 
  Ejemplo 1: Escaneo completo de un sitio web publico
  ----------------------------------------------------
    ./webscan.sh -u https://miempresa.com
 
    Genera una carpeta en ~/Desktop con los tres informes.
    Tiempo estimado: 3-8 minutos segun la velocidad de la red.
 
 
  Ejemplo 2: Escaneo rapido solo de cabeceras
  -------------------------------------------
    ./webscan.sh -u https://miempresa.com --only headers
 
    Tiempo estimado: menos de 10 segundos.
    Util para verificar rapidamente la configuracion de cabeceras HTTP.
 
 
  Ejemplo 3: Analisis de un servidor en red interna
  --------------------------------------------------
    ./webscan.sh -u http://192.168.1.100:8080 -t 20 -o /tmp/scan_interno
 
    Usa timeout de 20s para redes lentas. Guarda resultados en /tmp.
 
 
  Ejemplo 4: Verificacion post-despliegue (CI/CD)
  ------------------------------------------------
    ./webscan.sh -u https://staging.miempresa.com --only headers \
                 -o /var/reports/scan_$(date +%Y%m%d)
 
    Comprueba solo cabeceras de seguridad como check post-despliegue.
 
 
  Ejemplo 5: Busqueda especifica de SSTI en app Flask
  ----------------------------------------------------
    ./webscan.sh -u https://app-flask.com --only ssti
 
    Prueba 13 motores de plantillas en 26 parametros y 3 metodos HTTP.
 
 
  Ejemplo 6: Escaneo en Windows con WSL2
  ----------------------------------------
    ./webscan.sh -u https://objetivo.com -o /mnt/c/Users/Ana/Desktop/scan
 
    Guarda los informes directamente en el Escritorio de Windows.
 
 
================================================================================
  10. PREGUNTAS FRECUENTES (FAQ)
================================================================================
 
  P: El script dice que no puede conectar al objetivo. Que hago?
  R: Verificar que la URL es correcta y que el objetivo es accesible
     desde tu red con: curl -I https://tu-objetivo.com
     Si usas proxy corporativo, configura: export https_proxy=http://proxy:8080
 
  P: El escaneo es muy lento. Como lo acelero?
  R: Reducir el timeout: ./webscan.sh -u https://objetivo.com -t 5
     O ejecutar solo los modulos necesarios con --only.
 
  P: No aparece la carpeta en el Escritorio. Donde estan los informes?
  R: En sistemas sin entorno grafico o en WSL, ~/Desktop puede no existir.
     Usa: ./webscan.sh -u https://objetivo.com -o /tmp/mis-informes
     Los informes estaran en /tmp/mis-informes/
 
  P: El informe HTML se ve en blanco o roto.
  R: El HTML usa CSS moderno. Usar un navegador actualizado (Chrome, Firefox,
     Edge). No abrirlo con Internet Explorer ni Edge Legacy.
 
  P: El modulo SQLi no detecta nada. Significa que no hay SQLi?
  R: No necesariamente. La herramienta realiza pruebas automatizadas. Un
     SQLi oculto en parametros POST profundos o detras de autenticacion
     requiere pruebas manuales adicionales.
 
  P: Puedo usar esta herramienta en sistemas de terceros?
  R: Solo si tienes autorizacion ESCRITA del propietario del sistema.
     Ver seccion 12 (Aviso Legal).
 
  P: La herramienta modifica datos en la base de datos del objetivo?
  R: No. Los payloads son de lectura/deteccion. No ejecutan INSERT, UPDATE
     ni DELETE. La unica excepcion son los payloads de SQLi que incluyen
     "DROP TABLE" pero solo como string de prueba; un sistema correctamente
     parametrizado los ignorara.
 
  P: Necesito instalar algo mas para que funcione?
  R: Solo necesitas curl y Python 3. Ambos vienen preinstalados en la
     mayoria de distribuciones Linux y macOS modernos.
 
  P: El script genera un error de Python con f-string?
  R: Asegurate de tener Python 3.6+. En Python 3.5 o inferior los f-strings
     no estan disponibles. Actualizar con:
     sudo apt update && sudo apt install python3
 
 
================================================================================
  11. LIMITACIONES CONOCIDAS
================================================================================
 
  1. Analisis sin autenticacion
     La herramienta no soporta autenticacion. Solo analiza las paginas y
     endpoints accesibles sin sesion iniciada. Los problemas de seguridad
     detras de login requieren pruebas manuales o herramientas especializadas
     como Burp Suite.
 
  2. JavaScript dinamico (SPA/React/Angular)
     No ejecuta JavaScript. Las aplicaciones de pagina unica (SPA) que
     cargan contenido de forma dinamica pueden no ser analizadas en su
     totalidad. Para estas aplicaciones usar Burp Suite o OWASP ZAP.
 
  3. Falsos positivos
     Algunos servidores devuelven paginas de error con contenido que puede
     coincidir con los patrones de deteccion. Verificar siempre los
     hallazgos manualmente antes de incluirlos en un informe oficial.
 
  4. Falsos negativos
     La herramienta no garantiza la deteccion de todas las vulnerabilidades
     existentes. Un resultado limpio no equivale a un sistema seguro.
 
  5. Rate limiting y WAF
     Si el objetivo tiene un WAF (Web Application Firewall) o rate limiting,
     puede bloquear las peticiones del escaner y generar falsos negativos.
     Los escaneos pueden quedar registrados en los logs del objetivo.
 
  6. Alcance de red
     Solo accede a lo que es alcanzable desde la maquina donde se ejecuta.
     No escala a subdominios ni realiza enumeracion de directorios extensa.
 
  7. No es un sustituto del pentest manual
     Esta herramienta automatiza comprobaciones conocidas y documentadas.
     Un pentest manual realizado por un profesional puede detectar
     vulnerabilidades logicas, de control de acceso y de negocio que
     ninguna herramienta automatizada puede cubrir.
 
 
================================================================================
  12. AVISO LEGAL
================================================================================
 
  IMPORTANTE — LEER ANTES DE USAR
 
  Esta herramienta ha sido desarrollada exclusivamente para:
 
    - Pruebas de seguridad en sistemas PROPIOS.
    - Auditorias con AUTORIZACION ESCRITA PREVIA del propietario del sistema.
    - Entornos de laboratorio y formacion en ciberseguridad.
 
  PROHIBICIONES:
 
    Queda EXPRESAMENTE PROHIBIDO el uso de esta herramienta sobre sistemas,
    aplicaciones o infraestructuras para los que no se disponga de
    autorizacion expresa y documentada del propietario.
 
  RESPONSABILIDAD:
 
    El uso no autorizado de herramientas de escaneo y deteccion de
    vulnerabilidades puede constituir un delito informatico tipificado en:
 
      - Espana: Articulo 197 bis y 264 del Codigo Penal.
      - Union Europea: Directiva NIS2 y Directiva 2013/40/UE.
      - USA: Computer Fraud and Abuse Act (CFAA).
 
    El autor de esta herramienta declina toda responsabilidad por usos
    no autorizados o ilegales. El usuario asume total responsabilidad
    civil y penal derivada del uso de esta herramienta.
 
  RECOMENDACION:
 
    Antes de cualquier escaneo, obtener siempre autorizacion escrita que
    especifique el alcance, las fechas y los sistemas autorizados.
    Conservar dicha autorizacion durante y despues del trabajo.
 
================================================================================
  WebScan Pro v2.0  |  Manual de Usuario  |  Marzo 2026  |  CONFIDENCIAL
================================================================================
 
