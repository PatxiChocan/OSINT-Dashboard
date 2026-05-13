import threading
import uuid
import time
import socket
import subprocess
import re
import xml.etree.ElementTree as ET
import requests
import os
from datetime import datetime, timezone, timedelta

_pipelines: dict = {}
_lock = threading.Lock()

SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
INTELX_KEY = os.environ.get("INTELX_API_KEY", "")
VT_KEY     = os.environ.get("VIRUSTOTAL_API_KEY", "")

_IP_RE      = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_PRIVATE_RE = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)')
_EMAIL_RE   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# Puertos con descripción y riesgo
PORT_INFO = {
    21:    ("FTP", "high",
            "El protocolo FTP transmite credenciales y datos completamente en texto plano, sin ningún tipo de cifrado. "
            "Cualquier atacante con capacidad de interceptar el tráfico de red puede capturar usuario, contraseña y "
            "archivos transferidos. Además, versiones antiguas de servidores FTP (ProFTPD, vsftpd) acumulan CVEs "
            "con exploits públicos que permiten ejecución remota de código sin autenticación."),
    22:    ("SSH", "medium",
            "SSH proporciona acceso remoto cifrado al servidor. Sin embargo, versiones desactualizadas pueden contener "
            "vulnerabilidades críticas (como el ataque Terrapin en OpenSSH < 9.6). Los ataques de fuerza bruta y "
            "credential stuffing contra SSH son automatizados y continuos en Internet — un sistema con contraseñas "
            "débiles o sin autenticación por clave puede ser comprometido en minutos."),
    23:    ("Telnet", "critical",
            "Telnet es un protocolo completamente inseguro que transmite todas las comunicaciones, incluyendo "
            "credenciales de acceso, en texto plano. No existe ningún escenario legítimo en el que Telnet deba "
            "estar accesible desde Internet. Cualquier atacante que intercepte el tráfico obtiene acceso completo "
            "al sistema de forma inmediata. Este servicio debe ser deshabilitado y sustituido por SSH."),
    25:    ("SMTP", "medium",
            "Un servidor SMTP expuesto directamente a Internet puede estar mal configurado como relay abierto, "
            "lo que permitiría a cualquier atacante enviar correo suplantando la organización (spam, phishing). "
            "También revela información sobre la infraestructura de correo y puede ser objetivo de enumeración "
            "de usuarios válidos mediante el comando VRFY."),
    53:    ("DNS", "medium",
            "Un servidor DNS expuesto a Internet puede permitir la transferencia de zona completa (AXFR), "
            "revelando todos los subdominios y la estructura interna de la red. También puede ser abusado "
            "para amplificación de ataques DDoS, utilizando el servidor como reflector para multiplicar "
            "el tráfico de ataque hasta 100 veces hacia un objetivo."),
    80:    ("HTTP", "low",
            "El servidor web responde en HTTP sin cifrado. Toda la comunicación entre el cliente y el servidor "
            "viaja en texto plano, incluyendo cookies de sesión y datos de formularios. Un atacante en posición "
            "de red intermedia puede interceptar y modificar el tráfico (ataque MITM). Se recomienda redirigir "
            "todo el tráfico a HTTPS."),
    110:   ("POP3", "high",
            "POP3 en el puerto 110 transmite credenciales de correo y mensajes sin ningún cifrado. "
            "Las contraseñas de los usuarios de correo son capturables en texto plano por cualquier atacante "
            "con acceso al segmento de red. Este puerto debería estar completamente deshabilitado y los "
            "clientes deben conectar exclusivamente por POP3S (puerto 995) con TLS obligatorio."),
    135:   ("RPC", "high",
            "El servicio RPC de Windows expuesto a Internet es un vector de ataque recurrente. Ha sido "
            "el punto de entrada de gusanos como Blaster y Sasser, y sigue siendo objetivo de exploits "
            "automáticos. Exponer RPC a Internet permite a atacantes enumerar servicios internos, "
            "realizar ataques de relay de credenciales NTLM y posiblemente ejecutar código de forma remota."),
    139:   ("NetBIOS", "high",
            "NetBIOS expuesto a Internet permite a atacantes enumerar recursos compartidos, usuarios y "
            "grupos del sistema sin autenticación. Es el precursor de ataques de relay NTLM y "
            "credential harvesting. Este servicio nunca debería ser accesible desde Internet; "
            "su exposición indica una configuración de firewall gravemente deficiente."),
    143:   ("IMAP", "medium",
            "IMAP sin cifrado expone credenciales de correo y el contenido de los mensajes en texto plano. "
            "Si el servidor no fuerza STARTTLS, las contraseñas y emails de todos los usuarios son "
            "interceptables en la red. Se debe deshabilitar IMAP plano (puerto 143) y exigir "
            "conexiones únicamente por IMAPS (puerto 993)."),
    389:   ("LDAP", "high",
            "LDAP expuesto permite realizar consultas anónimas al directorio corporativo, revelando "
            "usuarios, grupos, estructura organizativa y atributos sensibles del Active Directory. "
            "Un atacante puede usar esta información para planificar ataques de phishing dirigido, "
            "fuerza bruta de credenciales o escalada de privilegios dentro de la organización."),
    443:   ("HTTPS", "low",
            "Servidor web con cifrado TLS activo. El riesgo principal reside en configuraciones "
            "obsoletas (TLS 1.0/1.1, cifrados débiles, certificados caducados o autofirmados) "
            "que pueden ser explotadas para descifrar el tráfico o realizar ataques MITM. "
            "Se recomienda verificar la versión TLS, la cadena de certificados y la configuración de cifrados."),
    445:   ("SMB", "critical",
            "SMB expuesto a Internet es una de las configuraciones más peligrosas en ciberseguridad. "
            "Es el vector de entrada de EternalBlue (MS17-010), el exploit utilizado por WannaCry y NotPetya "
            "para propagarse de forma automática comprometiendo miles de sistemas. Cualquier versión de SMB "
            "expuesta a Internet debe bloquearse de inmediato en el firewall — no existe ningún caso de uso "
            "legítimo que justifique exponer SMB directamente a Internet."),
    1433:  ("MSSQL", "critical",
            "El servidor de base de datos Microsoft SQL Server está accesible directamente desde Internet. "
            "Esto permite a cualquier atacante intentar autenticarse contra la base de datos, explotar "
            "vulnerabilidades conocidas del motor SQL y, si obtiene acceso, ejecutar comandos del sistema "
            "operativo mediante xp_cmdshell. Las bases de datos nunca deben ser accesibles directamente "
            "desde Internet; el acceso debe limitarse a la red interna o VPN."),
    1521:  ("Oracle DB", "critical",
            "Base de datos Oracle Database accesible directamente desde Internet. Oracle acumula "
            "vulnerabilidades críticas publicadas en sus CPU (Critical Patch Update) trimestrales, "
            "muchas de ellas con exploits públicos. Un atacante puede intentar autenticarse, "
            "explotar vulnerabilidades del listener TNS o extraer datos sensibles sin pasar "
            "por ninguna capa de aplicación."),
    3306:  ("MySQL", "critical",
            "Base de datos MySQL accesible directamente desde Internet. Esto permite a cualquier "
            "atacante intentar autenticarse contra la base de datos sin pasar por ninguna capa de "
            "aplicación. Las bases de datos nunca deben ser accesibles desde Internet; el acceso "
            "debe limitarse a localhost o a la red interna mediante reglas de firewall estrictas. "
            "Una versión desactualizada de MySQL incrementa adicionalmente el riesgo por la "
            "presencia de vulnerabilidades sin parche."),
    3389:  ("RDP", "critical",
            "El escritorio remoto de Windows (RDP) está expuesto directamente a Internet, "
            "siendo uno de los vectores de ataque más explotados en la actualidad. Los ataques "
            "de fuerza bruta y credential stuffing son continuos y automatizados. BlueKeep "
            "(CVE-2019-0708) y DejaBlue permiten ejecución de código sin autenticación en "
            "versiones sin parche. Además, RDP ha sido el punto de entrada del 90% de los "
            "ataques de ransomware dirigido según múltiples informes de inteligencia."),
    5432:  ("PostgreSQL", "critical",
            "Base de datos PostgreSQL accesible directamente desde Internet. Permite a cualquier "
            "atacante intentar autenticarse y, si la configuración de pg_hba.conf es permisiva, "
            "podría obtener acceso sin credenciales. PostgreSQL incluye funciones como COPY TO/FROM "
            "y extensiones que pueden derivar en lectura/escritura de archivos del sistema o "
            "ejecución de código. Las bases de datos deben estar aisladas de Internet."),
    5900:  ("VNC", "critical",
            "VNC proporciona control remoto completo del escritorio y frecuentemente se despliega "
            "sin autenticación fuerte o con contraseñas triviales. Muchas implementaciones "
            "transmiten el tráfico sin cifrar. Un atacante que acceda al servicio VNC obtiene "
            "control visual y operativo total del sistema, equivalente a sentarse físicamente "
            "delante del equipo."),
    6379:  ("Redis", "critical",
            "Redis no tiene autenticación habilitada por defecto en versiones antiguas. "
            "Un atacante con acceso al puerto puede leer todas las claves almacenadas, "
            "sobrescribir datos en caché, y mediante técnicas conocidas (escritura de claves "
            "SSH authorized_keys o cron jobs) obtener ejecución de código remoto con los "
            "privilegios del proceso Redis, que frecuentemente corre como root."),
    465:   ("SMTPS", "medium",
            "Servidor SMTP con cifrado SSL/TLS. Verifica que el certificado sea válido (no autofirmado), "
            "que se use TLS ≥ 1.2 y que requiera autenticación obligatoria para el envío. "
            "Un servidor SMTP mal configurado puede actuar como relay abierto, permitiendo "
            "el envío de spam o phishing suplantando el dominio de la organización."),
    587:   ("SMTP Submission", "medium",
            "Puerto de envío de correo autenticado con soporte STARTTLS. Debe exigir autenticación "
            "obligatoria y no debe actuar como relay abierto. Si STARTTLS no es obligatorio, "
            "las credenciales de los usuarios de correo pueden transmitirse en texto plano. "
            "Verifica la configuración SPF, DKIM y DMARC para prevenir suplantación."),
    993:   ("IMAPS", "low",
            "Correo IMAP con cifrado SSL/TLS. Verifica que se use TLS ≥ 1.2, que el certificado "
            "sea válido y de una CA reconocida, y que se hayan desactivado los cifrados débiles. "
            "Una configuración correcta de IMAPS es segura, pero debe mantenerse actualizada."),
    995:   ("POP3S", "low",
            "Correo POP3 con cifrado SSL/TLS. Verifica que se use TLS ≥ 1.2, que el certificado "
            "sea válido y de una CA reconocida. Una configuración correcta es segura, "
            "pero se recomienda también desactivar el puerto POP3 sin cifrar (110)."),
    8080:  ("HTTP Alternativo", "medium",
            "Servidor web activo en el puerto 8080, frecuentemente utilizado para paneles de "
            "administración, interfaces de gestión o aplicaciones internas que no deberían "
            "estar expuestas públicamente. Sin cifrado — toda la comunicación viaja en texto plano. "
            "Revisar si este servicio requiere exposición pública o si puede limitarse a la red interna."),
    8443:  ("HTTPS Alternativo", "medium",
            "Servidor web cifrado en el puerto 8443, habitualmente utilizado por paneles de "
            "administración (Plesk, cPanel, Webmin) o aplicaciones de gestión internas. "
            "Revisar si la exposición pública está justificada y verificar la versión TLS "
            "y la validez del certificado."),
    9080:  ("HTTP Alternativo (9080)", "medium",
            "Puerto web no estándar activo. Frecuentemente asociado a servidores de aplicaciones "
            "como Apache Tomcat o interfaces de administración internas. Sin cifrado. "
            "Revisar si la exposición es intencional y si requiere autenticación robusta."),
    9090:  ("HTTP Alternativo (9090)", "medium",
            "Puerto web no estándar activo. Asociado frecuentemente a interfaces de administración "
            "o aplicaciones internas. Sin cifrado. Revisar si la exposición pública es necesaria "
            "y si el servicio tiene autenticación habilitada."),
    9200:  ("Elasticsearch", "critical",
            "Elasticsearch no tiene autenticación habilitada por defecto en versiones antiguas. "
            "Un atacante con acceso al puerto puede leer, modificar o eliminar todos los índices "
            "sin ninguna credencial. Miles de instancias de Elasticsearch han sido comprometidas "
            "y sus datos filtrados o borrados por ransomware. El acceso debe restringirse "
            "estrictamente a la red interna."),
    27017: ("MongoDB", "critical",
            "MongoDB no tiene autenticación habilitada por defecto en su configuración inicial. "
            "Un atacante puede conectarse, leer todas las bases de datos y colecciones, "
            "exportar datos completos o sobrescribirlos. Esta configuración ha sido responsable "
            "de numerosas filtraciones masivas de datos. El servicio nunca debe ser "
            "accesible desde Internet."),
    50000: ("SAP", "high",
            "El puerto 50000 está asociado a servicios SAP (ICM o Message Server). "
            "Los sistemas ERP de SAP gestionan los datos más críticos de la organización "
            "(financieros, RRHH, supply chain). Una exposición sin control puede permitir "
            "acceso no autorizado a datos corporativos sensibles o explotación de "
            "vulnerabilidades conocidas de SAP con exploits públicos disponibles."),

    # ── Protocolos OT/ICS/SCADA ──────────────────────────────────────────────
    102:   ("Siemens S7 (ISO-TSAP)",  "critical","PLC Siemens expuesto. Permite leer/escribir variables de proceso y reprogramar el autómata sin autenticación."),
    502:   ("Modbus",                 "critical","Protocolo industrial sin autenticación. Permite leer/escribir registros de PLCs, actuadores y sensores directamente."),
    1911:  ("Niagara Fox (Tridium)",  "critical","Plataforma BMS/HVAC (Tridium Niagara). Controla climatización, accesos y sistemas de edificio. Sin cifrado por defecto."),
    2404:  ("IEC 60870-5-104",        "critical","Protocolo de telecontrol para infraestructura eléctrica (subestaciones, red de distribución). Exposición crítica."),
    4840:  ("OPC UA",                 "high",    "Protocolo OPC UA de comunicación industrial. Revisar autenticación, certificados y versión del servidor (vulnerabilidades conocidas en implementaciones antiguas)."),
    9600:  ("OMRON FINS",             "critical","Protocolo OMRON FINS sin autenticación. Permite acceso completo a PLCs OMRON: lectura/escritura de memoria y E/S."),
    18245: ("GE SRTP",                "critical","Protocolo GE SRTP para PLCs Series 90. Acceso sin autenticación a lógica de control y datos de proceso."),
    20000: ("DNP3",                   "critical","Protocolo DNP3 usado en infraestructura eléctrica y agua. Sin autenticación por defecto — permite enviar comandos a RTUs y subestaciones."),
    44818: ("EtherNet/IP (ENIP/CIP)", "critical","Protocolo EtherNet/IP de Rockwell/Allen-Bradley. Acceso a PLCs industriales sin autenticación — lectura/escritura de datos de proceso."),
    47808: ("BACnet",                 "critical","Protocolo BACnet para automatización de edificios (HVAC, iluminación, accesos, ascensores). Expuesto sin autenticación."),
    1962:  ("PCWorx",                 "critical","Protocolo Phoenix Contact PCWorx. Acceso a PLCs sin autenticación — lectura/escritura de programa y datos."),
    789:   ("Red Lion Crimson",       "high",    "Protocolo Red Lion Crimson v3. HMIs y gateways industriales expuestos. Vulnerabilidades conocidas en versiones antiguas."),
    4000:  ("Emerson ROC",            "high",    "Protocolo Emerson ROC para controladores de campo (petróleo y gas). Posible acceso sin autenticación a datos de proceso."),
}

RISKY_PORTS = set(PORT_INFO.keys())

# Subdominios de alto interés por nombre
INTERESTING_SUBS = {
    "ftp":      ("critical", "Servidor FTP expuesto", "FTP transfiere datos sin cifrado. Cierra o reemplaza por SFTP."),
    "smtp":     ("high",     "Servidor SMTP expuesto", "Verifica que no sea relay abierto y que use TLS."),
    "mail":     ("medium",   "Infraestructura de correo expuesta", "Asegura SPF, DKIM y DMARC correctamente configurados."),
    "webmail":  ("medium",   "Webmail expuesto", "Acceso web al correo corporativo. Asegura MFA y versión actualizada."),
    "owa":      ("high",     "Outlook Web Access (OWA) expuesto", "Panel de Exchange expuesto. Vector frecuente de ataques de credenciales."),
    "vpn":      ("medium",   "Servidor VPN expuesto", "Verifica versión y que no tenga vulnerabilidades conocidas (Fortinet, Pulse, etc.)."),
    "admin":    ("high",     "Panel de administración expuesto", "Paneles de admin no deben ser accesibles desde Internet."),
    "dev":      ("high",     "Entorno de desarrollo expuesto", "Los entornos dev suelen tener menos controles de seguridad."),
    "staging":  ("high",     "Entorno de staging expuesto", "Puede contener versiones desactualizadas o datos reales."),
    "test":     ("high",     "Entorno de pruebas expuesto", "Entornos de test frecuentemente sin medidas de seguridad."),
    "api":      ("medium",   "API expuesta", "Revisa autenticación, rate limiting y que no exponga datos sensibles."),
    "portal":   ("medium",   "Portal de cliente/empleado expuesto", "Verifica autenticación fuerte y control de acceso."),
    "remote":   ("high",     "Acceso remoto expuesto", "Acceso remoto directo a Internet es un riesgo alto."),
    "citrix":   ("high",     "Citrix expuesto", "Plataforma de virtualización — revisar versión y CVEs recientes."),
    "git":      ("critical", "Repositorio Git expuesto", "Puede contener código fuente, credenciales y secretos."),
    "jenkins":  ("critical", "Jenkins expuesto", "Sistema CI/CD — frecuentemente usado para movimiento lateral."),
    "jira":     ("medium",   "Jira expuesto", "Gestión de proyectos — puede filtrar información interna."),
    "confluence":("medium",  "Confluence expuesto", "Wiki corporativa — puede contener documentación sensible."),

    # ── OT / ICS / SCADA ─────────────────────────────────────────────────────
    "scada":     ("critical", "Interfaz SCADA expuesta", "Sistema de supervisión y control industrial accesible desde Internet. Riesgo de consecuencias físicas. Aisla inmediatamente detrás de VPN o firewall."),
    "ics":       ("critical", "Sistema de Control Industrial (ICS) expuesto", "Infraestructura de control industrial accesible públicamente. Segmenta y protege con acceso privilegiado (PAM/jump host)."),
    "plc":       ("critical", "PLC expuesto", "Controlador lógico programable accesible desde Internet — permite reprogramación y manipulación de procesos físicos."),
    "hmi":       ("critical", "HMI (Interfaz Hombre-Máquina) expuesta", "Panel de operación industrial accesible públicamente. Vector directo de manipulación de procesos físicos."),
    "historian":  ("high",    "Historian industrial expuesto", "Base de datos de series temporales de proceso (OSIsoft PI, Wonderware, etc.). Puede filtrar datos operacionales y de producción sensibles."),
    "dcs":       ("critical", "Sistema de Control Distribuido (DCS) expuesto", "DCS accesible desde Internet — control directo sobre procesos de producción continuos (químico, petroquímico, energía)."),
    "rtu":       ("critical", "RTU (Unidad Terminal Remota) expuesta", "RTU accesible públicamente — control de infraestructura crítica distribuida (agua, gas, electricidad)."),
    "ems":       ("critical", "EMS (Sistema de Gestión de Energía) expuesto", "Sistema de gestión de red eléctrica accesible desde Internet. Impacto potencial en suministro eléctrico."),
    "bms":       ("critical", "BMS (Sistema de Gestión de Edificio) expuesto", "Control de climatización, accesos, iluminación y ascensores accesible públicamente. Riesgo físico y de seguridad."),
    "bacnet":    ("critical", "Servidor BACnet expuesto", "Protocolo BACnet de automatización de edificios expuesto. Sin autenticación — control total sobre HVAC, accesos y sistemas del edificio."),
    "modbus":    ("critical", "Servidor Modbus expuesto", "Protocolo Modbus industrial expuesto — sin autenticación ni cifrado. Acceso directo a registros de PLCs y sensores."),
    "opcua":     ("high",     "Servidor OPC UA expuesto", "Middleware de comunicación industrial OPC UA accesible públicamente. Revisa autenticación y versión del servidor."),
    "opcda":     ("critical", "Servidor OPC DA expuesto", "OPC Data Access clásico — protocolo DCOM sin cifrado, expuesto a Internet. Vector de ataque frecuente en entornos legacy."),
    "niagara":   ("critical", "Plataforma Niagara (Tridium) expuesta", "Framework BMS Tridium Niagara accesible públicamente. Vulnerabilidades críticas conocidas. Control total del edificio."),
    "ignition":  ("high",     "Ignition SCADA expuesto", "Plataforma SCADA Ignition (Inductive Automation) accesible desde Internet. Revisa autenticación y versión."),
    "wonderware":("high",     "Wonderware expuesto", "SCADA/Historian Wonderware/AVEVA accesible públicamente. Puede filtrar datos de proceso y permitir control remoto no autorizado."),
}

SESSION = requests.Session()
SESSION.verify = False
import urllib3; urllib3.disable_warnings()


# ── Lifecycle ──────────────────────────────────────────────────────────────────

def calculate_score(findings):
    """Score de exposición 0-100. Mayor score = mayor riesgo."""
    c = sum(1 for f in findings if f["severity"] == "critical")
    h = sum(1 for f in findings if f["severity"] == "high")
    m = sum(1 for f in findings if f["severity"] == "medium")
    i = sum(1 for f in findings if f["severity"] == "info")

    pts  = min(c * 25, 50)
    pts += min(h * 10, 30)
    pts += min(m *  3, 15)
    pts += min(i *  1,  5)
    return min(100, pts)


def score_label(score):
    if score == 0:    return "Sin exposición detectada",    "low"
    if score <= 20:   return "Exposición muy baja",         "low"
    if score <= 40:   return "Exposición baja",             "low"
    if score <= 60:   return "Exposición moderada",         "medium"
    if score <= 75:   return "Exposición alta",             "high"
    if score <= 89:   return "Exposición muy alta",         "high"
    return                   "Exposición crítica",          "critical"


def create_pipeline(seeds):
    pid = str(uuid.uuid4())
    with _lock:
        _pipelines[pid] = {"status": "running", "events": [], "findings": [], "_seen": set(), "assets": [], "seeds": seeds}
    threading.Thread(target=_run, args=(pid, seeds), daemon=True).start()
    return pid


def create_pipeline_single(tool, target):
    """Ejecuta un único módulo del pipeline sobre un objetivo."""
    pid = str(uuid.uuid4())
    with _lock:
        _pipelines[pid] = {"status": "running", "events": [], "findings": [], "_seen": set(), "assets": [target], "seeds": [target]}
    threading.Thread(target=_run_single, args=(pid, tool, target), daemon=True).start()
    return pid


def _run_single(pid, tool, target):
    atype = _asset_type(target)
    try:
        _push(pid, {"type": "asset_start", "asset": target, "asset_type": atype})
        _log(pid, f"▶ Módulo '{tool}' sobre {target}")

        if   tool == "whois":          _whois(pid, target)
        elif tool == "dns":            _dns(pid, target)
        elif tool == "subfinder":      _subfinder(pid, target); _crtsh(pid, target)
        elif tool == "nmap":           _nmap(pid, target)
        elif tool == "shodan_host":    _shodan_host(pid, target); _internetdb(pid, target)
        elif tool == "shodan_domain":  _shodan_domain(pid, target)
        elif tool == "virustotal":
            if atype == "ip": _virustotal_ip(pid, target)
            else:             _virustotal_domain(pid, target)
        elif tool == "urlscan":        _urlscan(pid, target)
        elif tool == "intelx":         _intelx(pid, target)
        elif tool == "intelx_domain":  _intelx(pid, f"@{target}")
        elif tool == "harvester":      _harvester(pid, target)
        elif tool == "variants":       _domain_variants(pid, target)
        elif tool == "blackbird":      _blackbird(pid, target)
        elif tool == "sherlock":       _sherlock(pid, target)
        elif tool == "maigret":        _maigret(pid, target)
        elif tool == "full_domain":
            _whois(pid, target); _dns(pid, target)
            _subfinder(pid, target); _crtsh(pid, target)
            _shodan_domain(pid, target); _virustotal_domain(pid, target)
            _urlscan(pid, target); _intelx(pid, target)
            _intelx(pid, f"@{target}"); _domain_variants(pid, target)
            _harvester(pid, target)
        elif tool == "full_ip":
            _nmap(pid, target); _shodan_host(pid, target)
            _internetdb(pid, target); _virustotal_ip(pid, target)
        else:
            _err(pid, f"Módulo desconocido: {tool}")

        _push(pid, {"type": "asset_done", "asset": target})
    except Exception as e:
        _err(pid, f"[{tool}] Error: {e}")
    finally:
        findings = get_findings(pid)
        score    = calculate_score(findings)
        lbl, _   = score_label(score)
        _log(pid, f"\n✓ Completado — {len(findings)} hallazgos · Score {score}/100 ({lbl})")
        _push(pid, {"type": "pipeline_complete", "score": score, "score_label": lbl})
        with _lock:
            if pid in _pipelines:
                _pipelines[pid]["status"] = "done"
                _pipelines[pid]["score"]  = score


def get_pipeline_data(pid):
    with _lock:
        p = _pipelines.get(pid)
        if not p:
            return None
        return {
            "seeds":    p.get("seeds", []),
            "assets":   p.get("assets", []),
            "score":    p.get("score", 0),
            "findings": p.get("findings", []),
            "status":   p.get("status", ""),
        }

def get_events(pid, from_idx=0):
    with _lock:
        p = _pipelines.get(pid)
        if not p: return None, None
        return p["events"][from_idx:], p["status"]

def get_findings(pid):
    with _lock:
        p = _pipelines.get(pid)
        return p["findings"] if p else []

def _push(pid, ev):
    with _lock:
        if pid in _pipelines:
            _pipelines[pid]["events"].append(ev)

def _log(pid, msg):  _push(pid, {"type": "stage",   "msg": msg})
def _err(pid, msg):  _push(pid, {"type": "error",   "msg": msg})

def _finding(pid, asset, tool, severity, title, detail, rec=""):
    # Dedup key: mismo activo + título normalizado — herramienta excluida para eliminar
    # duplicados cross-tool (subfinder + crt.sh, nmap + shodan en mismo puerto, etc.)
    dedup_key = (asset.lower(), title.strip()[:80].lower())
    with _lock:
        p = _pipelines.get(pid)
        if not p:
            return
        if dedup_key in p["_seen"]:
            return
        p["_seen"].add(dedup_key)
        f = {"asset": asset, "tool": tool, "severity": severity,
             "title": title, "detail": detail, "recommendation": rec}
        p["findings"].append(f)
    _push(pid, {"type": "finding", **f})

def _is_ip(s):       return bool(_IP_RE.fullmatch(s.strip()))
def _is_public(ip):  return not _PRIVATE_RE.match(ip)
def _is_email(s):    return bool(_EMAIL_RE.fullmatch(s.strip()))
def _asset_type(s):
    if _is_ip(s):    return "ip"
    if _is_email(s): return "email"
    return "domain"

def _usernames_from_email(email):
    local = email.split("@")[0].lower()
    c = {local, local.replace(".", ""), local.replace(".", "_")}
    if "." in local: c.add(local.split(".")[0])
    return list(c)


# ══════════════════════════════════════════════════════════════════════════════
# FASE 1 — DOMINIO
# ══════════════════════════════════════════════════════════════════════════════

def _whois(pid, domain):
    _log(pid, f"[WHOIS] Consultando registro de {domain}...")
    usernames = []
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15).stdout
        fields = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip().lower(); v = v.strip()
                if v and k not in fields:
                    fields[k] = v

        registrant  = fields.get("registrant name") or fields.get("registrant") or "Privado / Oculto"
        registrar   = fields.get("registrar", "—")
        created     = fields.get("creation date") or fields.get("created", "—")
        expires_raw = fields.get("registry expiry date") or fields.get("expiry date") or fields.get("expires", "")
        nameservers = [v for k, v in fields.items() if "name server" in k or "nserver" in k]
        privacy     = "redacted" in registrant.lower() or "privacy" in registrant.lower()

        detail_parts = [
            f"Registrante: {'[PRIVADO — datos ocultos por privacy protection]' if privacy else registrant}",
            f"Registrar: {registrar}",
            f"Fecha de creación: {created[:25] if created != '—' else '—'}",
            f"Expiración: {expires_raw[:25] if expires_raw else '—'}",
            f"Nameservers: {', '.join(nameservers[:4]) if nameservers else '—'}",
        ]

        # Alerta de expiración próxima
        expiry_warning = ""
        if expires_raw:
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d/%m/%Y"):
                try:
                    exp_dt = datetime.strptime(expires_raw[:19], fmt[:len(expires_raw[:19])])
                    days_left = (exp_dt - datetime.utcnow()).days
                    if days_left < 90:
                        expiry_warning = f"⚠ El dominio expira en {days_left} días ({expires_raw[:10]})."
                    break
                except Exception:
                    continue

        _finding(pid, domain, "whois", "high" if expiry_warning else "info",
                 f"Registro WHOIS de {domain}",
                 "\n".join(detail_parts) + (f"\n{expiry_warning}" if expiry_warning else ""),
                 expiry_warning if expiry_warning else
                 "Verifica que el registrante y nameservers sean los esperados. Renueva con antelación.")

        if privacy:
            _finding(pid, domain, "whois", "info",
                     "Privacy protection activa en WHOIS",
                     "Los datos del registrante están ocultos (privacy protection). "
                     "Esto es una buena práctica — impide correlacionar el dominio con datos personales.",
                     "Mantén la privacy protection activa.")

        # Extraer username del registrante solo si es un nombre real (no texto de privacy)
        skip_words = {"redacted", "privacy", "protected", "withheld", "masked", "hidden", "data"}
        if registrant and not privacy and " " in registrant and len(registrant) < 40:
            parts = registrant.lower().split()
            if len(parts) >= 2 and not any(w in skip_words for w in parts):
                usernames.extend([parts[0][0] + parts[-1], parts[0] + "." + parts[-1]])

    except FileNotFoundError:
        _log(pid, "[WHOIS] whois no instalado, omitiendo")
    except Exception as e:
        _err(pid, f"[WHOIS] Error: {e}")
    return usernames


def _dns_quick(pid, domain) -> list:
    """Solo resuelve IPs — para subdominios, sin análisis SPF/DMARC."""
    ips = set()
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET):
            ip = info[4][0]
            if _is_public(ip): ips.add(ip)
    except Exception:
        pass
    if ips:
        _log(pid, f"[DNS] {domain} → {', '.join(ips)}")
    return list(ips)


def _dns(pid, domain):
    _log(pid, f"[DNS] Analizando registros DNS de {domain}...")
    ips = set()

    # A records
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET):
            ip = info[4][0]
            if _is_public(ip): ips.add(ip)
        if ips:
            _finding(pid, domain, "dns", "info",
                     f"Registros A — IPs públicas de {domain}",
                     f"El dominio resuelve a: {', '.join(ips)}\n"
                     f"Estas IPs son el punto de entrada público de la infraestructura.",
                     "Verifica que solo estén expuestas las IPs estrictamente necesarias.")
    except Exception:
        pass

    # MX — infraestructura de correo
    try:
        mx_out = subprocess.run(["dig", "+short", "MX", domain],
                                capture_output=True, text=True, timeout=8).stdout.strip()
        if mx_out:
            _finding(pid, domain, "dns", "info",
                     f"Registros MX — Infraestructura de correo de {domain}",
                     f"Servidores de correo: {mx_out[:300]}\n"
                     f"Estos servidores gestionan el correo entrante de la organización.",
                     "Verifica SPF, DKIM y DMARC para proteger el correo de suplantación.")
    except Exception:
        pass

    # TXT — SPF / DMARC / DKIM
    try:
        txt_out = subprocess.run(["dig", "+short", "TXT", domain],
                                 capture_output=True, text=True, timeout=8).stdout.strip()
        if txt_out:
            has_spf   = "v=spf1"  in txt_out
            has_dmarc_check = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=8).stdout.strip()
            has_dmarc = bool(has_dmarc_check)

            if not has_spf:
                _finding(pid, domain, "dns", "high",
                         f"SPF no configurado en {domain}",
                         "No se detectó registro SPF en los TXT del dominio.\n"
                         "Sin SPF cualquiera puede enviar correos suplantando este dominio.",
                         "Configura un registro SPF: ej. 'v=spf1 include:tu-proveedor.com -all'")
            else:
                _finding(pid, domain, "dns", "info",
                         f"SPF configurado en {domain}",
                         f"SPF detectado: {[l for l in txt_out.splitlines() if 'spf1' in l][0][:200]}",
                         "Revisa que el SPF cubra todos los servidores de envío y use '-all' al final.")

            if not has_dmarc:
                _finding(pid, domain, "dns", "high",
                         f"DMARC no configurado en {domain}",
                         "No se detectó política DMARC (_dmarc.dominio).\n"
                         "Sin DMARC los correos falsos que pasen SPF/DKIM no se bloquean ni reportan.",
                         "Configura DMARC: 'v=DMARC1; p=reject; rua=mailto:dmarc@tudominio.com'")
            else:
                _finding(pid, domain, "dns", "info",
                         f"DMARC configurado en {domain}",
                         f"DMARC detectado: {has_dmarc_check[:200]}",
                         "Verifica que la política sea 'p=reject' para máxima protección.")
    except Exception:
        pass

    # NS
    try:
        ns_out = subprocess.run(["dig", "+short", "NS", domain],
                                capture_output=True, text=True, timeout=8).stdout.strip()
        if ns_out:
            _finding(pid, domain, "dns", "info",
                     f"Nameservers de {domain}",
                     f"DNS autoritativos: {ns_out[:200]}",
                     "Asegúrate de que los nameservers sean los correctos y estén configurados con DNSSEC si es posible.")
    except Exception:
        pass

    return list(ips)


def _subfinder(pid, domain):
    _log(pid, f"[Subfinder] Enumerando subdominios de {domain}...")
    subs = []
    try:
        out = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
            capture_output=True, text=True, timeout=60
        ).stdout.strip()
        subs = [s.strip() for s in out.splitlines() if s.strip()]
        if subs:
            _log(pid, f"[Subfinder] {len(subs)} subdominios encontrados")
            _analizar_subdominios(pid, domain, subs, "subfinder")
        else:
            _log(pid, "[Subfinder] Sin subdominios")
    except FileNotFoundError:
        _log(pid, "[Subfinder] No instalado, omitiendo")
    except Exception as e:
        _err(pid, f"[Subfinder] Error: {e}")
    return subs


def _crtsh(pid, domain):
    _log(pid, f"[crt.sh] Certificados SSL de {domain}...")
    subs = set()
    try:
        r = SESSION.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)
        if subs:
            _log(pid, f"[crt.sh] {len(subs)} subdominios en certificados")
            _analizar_subdominios(pid, domain, list(subs), "crt.sh")
        else:
            _log(pid, "[crt.sh] Sin resultados")
    except Exception as e:
        _err(pid, f"[crt.sh] Error: {e}")
    return list(subs)


def _analizar_subdominios(pid, domain, subs, tool):
    """Analiza la lista de subdominios y genera hallazgos por categoría y riesgo."""
    interesting = []
    random_looking = []
    normal = []

    for sub in subs:
        prefix = sub.replace(f".{domain}", "").split(".")[0].lower()
        if prefix in INTERESTING_SUBS:
            interesting.append((sub, prefix))
        elif re.match(r'^[a-z0-9]{10,}$', prefix):  # subdominio aleatorio
            random_looking.append(sub)
        else:
            normal.append(sub)

    # Hallazgo por subdominio interesante
    for sub, prefix in interesting:
        sev, title_suffix, rec = INTERESTING_SUBS[prefix]
        _finding(pid, sub, tool, sev,
                 f"{title_suffix}: {sub}",
                 f"Subdominio '{sub}' detectado — {INTERESTING_SUBS[prefix][1]}.\n"
                 f"Herramienta: {tool}. Este tipo de subdominio suele exponer servicios sensibles.",
                 rec)

    # Subdominios con nombre aleatorio (posible CDN o takeover risk)
    if random_looking:
        _finding(pid, domain, tool, "medium",
                 f"{len(random_looking)} subdominios con nombre aleatorio detectados",
                 f"Subdominios: {', '.join(random_looking[:10])}\n"
                 f"Los nombres aleatorios pueden indicar CDN, servicios de terceros o subdominios huérfanos "
                 f"susceptibles a subdomain takeover.",
                 "Verifica que estos subdominios estén activos y controlados. "
                 "Si apuntan a servicios externos ya no usados, elimínalos para evitar subdomain takeover.")

    # Resumen de todos
    if subs:
        _finding(pid, domain, tool, "info",
                 f"{len(subs)} subdominios encontrados con {tool}",
                 f"Lista completa: {', '.join(subs[:30])}{'...' if len(subs)>30 else ''}",
                 "Revisa que todos los subdominios sean legítimos y necesarios.")


def _shodan_domain(pid, domain):
    if not SHODAN_KEY: return []
    _log(pid, f"[Shodan] Servicios indexados de {domain}...")
    ips = set()
    try:
        r = SESSION.get("https://api.shodan.io/shodan/host/search",
                        params={"key": SHODAN_KEY, "query": f"hostname:{domain}"},
                        timeout=20)
        if r.status_code == 200:
            for m in r.json().get("matches", []):
                ip = m.get("ip_str", "")
                if ip and _is_public(ip):
                    ips.add(ip)
                    port    = m.get("port", "")
                    product = m.get("product", "")
                    version = m.get("version", "")
                    banner  = (m.get("data") or "")[:200].replace("\n", " ")
                    if port:
                        pinfo    = PORT_INFO.get(port, ("", "info", ""))
                        svc_str  = " ".join(filter(None, [product, version])).strip()
                        svc_id   = pinfo[0] if pinfo and pinfo[0] else (svc_str or f"puerto {port}")
                        port_ctx = pinfo[2] if pinfo and pinfo[2] else ""
                        shodandetail = (
                            f"Shodan ha indexado el puerto {port} abierto en {ip}. "
                            f"Servicio detectado: {svc_id}{f' ({svc_str})' if svc_str and svc_str != svc_id else ''}."
                        )
                        if port_ctx:
                            shodandetail += f"\n\n{port_ctx}"
                        if banner and not port_ctx:
                            shodandetail += f"\n\nBanner capturado: {banner}"
                        elif banner:
                            shodandetail += f"\n\nBanner capturado: {banner}"
                        _finding(pid, ip, "shodan", pinfo[1] if pinfo else "info",
                                 f"Puerto {port} ({svc_id}) indexado en Shodan — {ip}".strip(),
                                 shodandetail,
                                 f"Verifica que el puerto {port} deba estar accesible desde Internet. "
                                 f"Si el servicio no es necesario de forma pública, aplica reglas de "
                                 f"firewall para restringir el acceso.")
            if ips:
                _log(pid, f"[Shodan] {len(ips)} IPs indexadas: {', '.join(ips)}")
    except Exception as e:
        _err(pid, f"[Shodan] Error: {e}")
    return list(ips)


def _virustotal_domain(pid, domain):
    if not VT_KEY: return []
    _log(pid, f"[VirusTotal] Reputación de {domain}...")
    extra_ips = []
    try:
        r = SESSION.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                        headers={"x-apikey": VT_KEY}, timeout=20)
        if r.status_code != 200: return []
        attrs     = r.json().get("data", {}).get("attributes", {})
        stats     = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total     = sum(stats.values()) or 1
        cats      = set(attrs.get("categories", {}).values())

        cats_str = f" Categorías asignadas por los motores: {', '.join(cats)}." if cats else ""
        if malicious > 0:
            _finding(pid, domain, "virustotal", "critical",
                     f"{domain} marcado como MALICIOSO por {malicious}/{total} motores AV",
                     f"El dominio {domain} ha sido clasificado como malicioso por {malicious} de {total} "
                     f"motores antivirus y de reputación web analizados por VirusTotal. "
                     f"{suspicious} motores adicionales lo señalan como sospechoso.{cats_str}"
                     f"\n\nEsta clasificación indica que el dominio puede estar siendo utilizado para "
                     f"distribuir malware, alojar páginas de phishing o actuar como infraestructura de "
                     f"comando y control (C2). Una detección de esta magnitud requiere investigación inmediata.",
                     f"Investiga el dominio {domain} de inmediato. Comprueba si ha sido comprometido, "
                     f"si aloja contenido malicioso o si está siendo utilizado para suplantación de identidad. "
                     f"Considera bloquear el dominio en todos los perímetros de seguridad de la organización.")
        elif suspicious > 0:
            _finding(pid, domain, "virustotal", "medium",
                     f"{domain} marcado como sospechoso por {suspicious}/{total} motores AV",
                     f"El dominio {domain} ha sido señalado como sospechoso por {suspicious} de {total} "
                     f"motores de reputación analizados por VirusTotal. Aunque no hay una clasificación "
                     f"maliciosa definitiva, la presencia de alertas sospechosas puede indicar actividad "
                     f"no deseada o uso indebido reciente del dominio.{cats_str}",
                     f"Monitoriza el dominio {domain} y revisa registros de acceso recientes. "
                     f"Si el dominio pertenece a la organización, investiga si ha sido comprometido o "
                     f"utilizado de forma no autorizada.")
        else:
            _finding(pid, domain, "virustotal", "info",
                     f"{domain} sin detecciones en VirusTotal ({total} motores)",
                     f"El dominio {domain} no presenta alertas de seguridad en ninguno de los {total} "
                     f"motores de reputación analizados por VirusTotal.{cats_str} "
                     f"Esto indica una reputación limpia en las fuentes de inteligencia de amenazas consultadas.",
                     "Continúa monitorizando periódicamente la reputación del dominio. "
                     "La ausencia de alertas actuales no garantiza que no aparezcan en el futuro.")

        for rec in attrs.get("last_dns_records", []):
            if rec.get("type") == "A":
                ip = rec.get("value", "")
                if _is_ip(ip) and _is_public(ip):
                    extra_ips.append(ip)
    except Exception as e:
        _err(pid, f"[VirusTotal] Error dominio: {e}")
    return extra_ips


def _urlscan(pid, domain):
    _log(pid, f"[urlscan] Análisis web de {domain}...")
    ips = []
    try:
        r = SESSION.get("https://urlscan.io/api/v1/search/",
                        params={"q": f"domain:{domain}", "size": 10},
                        headers={"User-Agent": "AletheiaOSINT/1.0"}, timeout=15)
        if r.status_code != 200: return []
        results   = r.json().get("results", [])
        malicious = [x for x in results if x.get("verdicts", {}).get("overall", {}).get("malicious")]
        techs_all = set()
        for item in results:
            ip = item.get("page", {}).get("ip", "")
            if ip and _is_public(ip) and ip not in ips:
                ips.append(ip)
            for t in item.get("verdicts", {}).get("overall", {}).get("tags", []):
                techs_all.add(t)

        _log(pid, f"[urlscan] {len(results)} escaneos previos para {domain}")

        if results:
            sample = results[0]
            page   = sample.get("page", {})
            _finding(pid, domain, "urlscan", "critical" if malicious else "info",
                     f"urlscan: {'⚠ MALICIOSO' if malicious else 'Análisis web'} de {domain}",
                     f"Escaneos previos: {len(results)} | IP: {page.get('ip','—')} | País: {page.get('country','—')}\n"
                     f"Servidor: {page.get('server','—')} | ASN: {page.get('asnname','—')}\n"
                     f"Tags detectados: {', '.join(techs_all) if techs_all else '—'}\n"
                     f"Veredictos maliciosos: {len(malicious)}/{len(results)}",
                     "Revisa el contenido del sitio regularmente en urlscan.io" +
                     (" — SE HAN DETECTADO VEREDICTOS MALICIOSOS." if malicious else "."))
    except Exception as e:
        _err(pid, f"[urlscan] Error: {e}")
    return ips


def _intelx(pid, asset):
    if not INTELX_KEY: return
    is_domain_emails = asset.startswith("@")
    label = f"emails '{asset}' (dominio)" if is_domain_emails else f"'{asset}'"
    _log(pid, f"[IntelX] Buscando {label} en filtraciones...")
    try:
        r = SESSION.post("https://2.intelx.io/intelligent/search",
                         headers={"x-key": INTELX_KEY},
                         json={"term": asset, "maxresults": 20, "media": 0,
                               "sort": 4, "terminate": []}, timeout=15)
        if r.status_code != 200: return
        sid = r.json().get("id", "")
        if not sid: return
        time.sleep(3)
        r2 = SESSION.get(f"https://2.intelx.io/intelligent/search/result?id={sid}&limit=20",
                         headers={"x-key": INTELX_KEY}, timeout=15)
        records = r2.json().get("records", []) if r2.status_code == 200 else []
        if records:
            buckets = {}
            for rec in records:
                bucket = rec.get("bucket", "desconocido")
                buckets[bucket] = buckets.get(bucket, 0) + 1
            bucket_detail = ", ".join(f"{k}: {v}" for k, v in buckets.items())
            if is_domain_emails:
                _finding(pid, asset, "intelx", "high",
                         f"{len(records)} credenciales/emails '{asset}' encontrados en filtraciones",
                         f"IntelX encontró {len(records)} registros con emails de este dominio corporativo en bases de datos comprometidas.\n"
                         f"Fuentes por tipo: {bucket_detail}\n"
                         f"Empleados con credenciales expuestas son un vector crítico de acceso inicial "
                         f"(credential stuffing, password spraying).",
                         "Identifica qué empleados tienen credenciales expuestas. "
                         "Forza cambio de contraseña y activa MFA para todas las cuentas corporativas.")
            else:
                _finding(pid, asset, "intelx", "high",
                         f"{len(records)} registros de '{asset}' en filtraciones / dark web",
                         f"IntelX encontró {len(records)} apariciones en bases de datos comprometidas.\n"
                         f"Fuentes por tipo: {bucket_detail}\n"
                         f"Esto indica que datos asociados a '{asset}' han sido expuestos en brechas de seguridad.",
                         "Revisa qué credenciales o datos están expuestos. "
                         "Cambia contraseñas afectadas y notifica a los usuarios si procede.")
        else:
            if is_domain_emails:
                _finding(pid, asset, "intelx", "info",
                         f"Sin credenciales de '{asset}' en filtraciones (IntelX)",
                         f"No se encontraron emails/credenciales del dominio '{asset}' en bases de datos de filtraciones conocidas.",
                         "Continúa monitorizando periódicamente.")
            else:
                _finding(pid, asset, "intelx", "info",
                         f"Sin filtraciones de '{asset}' en IntelX",
                         f"No se encontraron registros de '{asset}' en bases de datos de filtraciones conocidas.",
                         "Continúa monitorizando periódicamente.")
    except Exception as e:
        _err(pid, f"[IntelX] Error: {e}")


def _harvester(pid, domain):
    _log(pid, f"[theHarvester] Emails y subdominios de {domain}...")
    emails = []
    try:
        proc = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "crtsh,certspotter,hackertarget,duckduckgo"],
            capture_output=True, text=True, timeout=60
        )
        output = proc.stdout + proc.stderr
        found  = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), output)))
        emails = [e for e in found if _EMAIL_RE.fullmatch(e)]
        if emails:
            _finding(pid, domain, "harvester", "medium",
                     f"{len(emails)} emails corporativos expuestos públicamente",
                     f"Emails encontrados indexados en fuentes públicas:\n" +
                     "\n".join(f"  • {e}" for e in emails[:15]) +
                     (f"\n  ... y {len(emails)-15} más" if len(emails)>15 else "") +
                     "\n\nEstos emails pueden usarse para ataques de phishing dirigido (spear phishing) "
                     "o credential stuffing contra servicios corporativos.",
                     "Minimiza la exposición pública de emails corporativos. "
                     "Usa alias genéricos (info@, contacto@) en la web. "
                     "Forma a los empleados sobre phishing.")
            _log(pid, f"[theHarvester] {len(emails)} emails: {', '.join(emails[:5])}")
        else:
            _log(pid, "[theHarvester] Sin emails encontrados")
    except FileNotFoundError:
        _log(pid, "[theHarvester] No instalado, omitiendo")
    except Exception as e:
        _err(pid, f"[theHarvester] Error: {e}")
    return emails


# ══════════════════════════════════════════════════════════════════════════════
# FASE 2 — IPs
# ══════════════════════════════════════════════════════════════════════════════

def _nmap(pid, ip):
    _log(pid, f"[Nmap] Escaneando {ip} — puertos, versiones y scripts...")
    try:
        proc = subprocess.run(
            ["/usr/bin/nmap", "-sV", "-O", "--osscan-guess", "--open", "-T4", "--top-ports", "1000",
             "--script", "banner,http-title,ssl-cert,smtp-commands,ftp-anon",
             "--script-timeout", "10s",
             "-oX", "-", ip],
            capture_output=True, text=True, timeout=120
        )
        if not proc.stdout.strip():
            _log(pid, f"[Nmap] Sin output para {ip}")
            return

        root = ET.fromstring(proc.stdout)

        tcpwrapped_ports = []
        for port_el in root.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid   = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")
            svc      = port_el.find("service")
            name     = svc.get("name", "")    if svc is not None else ""
            product  = svc.get("product", "") if svc is not None else ""
            version  = svc.get("version", "") if svc is not None else ""
            extra    = svc.get("extrainfo","") if svc is not None else ""

            # tcpwrapped = port open but service refused identification; consolidate into one finding
            if name == "tcpwrapped" and not product and not version:
                has_script_output = any(
                    s.get("output", "").strip() and "ERROR:" not in s.get("output", "")
                    for s in port_el.findall("script")
                )
                if not has_script_output:
                    tcpwrapped_ports.append(portid)
                    continue

            pinfo = PORT_INFO.get(portid)
            sev   = pinfo[1] if pinfo else ("medium" if portid not in (80, 443) else "low")
            ctx   = pinfo[2] if pinfo else ""

            # Scripts output para este puerto
            scripts_txt = []
            vuln_found  = False
            for script in port_el.findall("script"):
                sid    = script.get("id", "")
                sout   = script.get("output", "").strip()
                if not sout:
                    continue
                # Ignorar scripts que fallaron (no son hallazgos reales)
                if "ERROR:" in sout and "Script execution failed" in sout:
                    continue
                scripts_txt.append(f"[{sid}]: {sout[:300]}")
                sout_upper = sout.upper()
                if "VULNERABLE" in sout_upper and "NOT VULNERABLE" not in sout_upper:
                    vuln_found = True

            if vuln_found:
                sev = "critical"

            svc_str = " ".join(filter(None, [product, version, extra])).strip()
            svc_id  = name
            if svc_str:
                svc_id += f" ({svc_str})"

            detail = f"Puerto {portid}/{protocol} abierto en {ip}. Servicio detectado: {svc_id}."
            if ctx:
                detail += f"\n\n{ctx}"
            if scripts_txt:
                detail += "\n\nDatos adicionales de detección:\n" + "\n".join(scripts_txt[:5])

            if vuln_found:
                rec_str = (
                    f"VULNERABILIDAD CONFIRMADA — Parchea o mitiga el servicio de inmediato. "
                    f"Considera desconectar temporalmente el puerto {portid} hasta que el parche esté aplicado."
                )
            elif pinfo:
                rec_str = (
                    f"Evalúa si el servicio {name} en el puerto {portid} debe estar accesible desde Internet. "
                    f"Si no es estrictamente necesario, aplica reglas de firewall para restringir el acceso."
                )
            else:
                rec_str = (
                    f"Verifica si el puerto {portid}/{protocol} debe estar expuesto. "
                    f"Si el servicio no es necesario, ciérralo mediante firewall."
                )
            _finding(pid, ip, "nmap", sev,
                     f"{'VULNERABLE — ' if vuln_found else ''}"
                     f"Puerto {portid}/{protocol} abierto: {svc_id}".strip(),
                     detail,
                     rec_str)

        if tcpwrapped_ports:
            ports_list = ", ".join(str(p) for p in sorted(tcpwrapped_ports))
            _finding(pid, ip, "nmap", "info",
                     f"{len(tcpwrapped_ports)} puertos tcpwrapped (servicio no identificado)",
                     f"Nmap detectó {len(tcpwrapped_ports)} puertos abiertos sin identificar el servicio "
                     f"(tcpwrapped — el servicio rechazó la identificación o está filtrado por TCP wrapper).\n"
                     f"Puertos: {ports_list}\n\n"
                     f"Esto puede indicar servicios detrás de un firewall o TCP wrapper, "
                     f"o servicios que rechazan conexiones no autorizadas.",
                     "Investiga manualmente estos puertos si son relevantes para el negocio. "
                     "Si no son necesarios, ciérralos en el firewall.")

        # OS detection
        os_matches = []
        for osmatch in root.findall('.//osmatch'):
            name_os   = osmatch.get('name', '')
            accuracy  = osmatch.get('accuracy', '')
            os_class  = osmatch.find('osclass')
            vendor    = os_class.get('vendor', '') if os_class is not None else ''
            osfamily  = os_class.get('osfamily', '') if os_class is not None else ''
            osgen     = os_class.get('osgen', '') if os_class is not None else ''
            if name_os:
                os_matches.append({
                    "name": name_os,
                    "accuracy": accuracy,
                    "vendor": vendor,
                    "family": osfamily,
                    "gen": osgen,
                })
        if os_matches:
            best = os_matches[0]
            lines = [f"  • {m['name']} — {m['accuracy']}% certeza" for m in os_matches[:4]]
            detail_os = (
                f"Sistema operativo más probable: {best['name']} ({best['accuracy']}% certeza)\n"
                f"Familia: {best['vendor']} {best['family']} {best['gen']}".strip() + "\n\n"
                "Candidatos detectados por Nmap:\n" + "\n".join(lines)
            )
            _finding(pid, ip, "nmap", "info",
                     f"OS detectado: {best['name']}",
                     detail_os,
                     "Verifica que el sistema operativo esté actualizado y parcheado. "
                     "Sistemas sin soporte (EOL) son un riesgo crítico.")

    except subprocess.TimeoutExpired:
        _err(pid, f"[Nmap] Timeout en {ip}")
    except ET.ParseError:
        _err(pid, f"[Nmap] Error parseando XML de {ip}")
    except FileNotFoundError:
        _err(pid, "[Nmap] nmap no encontrado")
    except Exception as e:
        _err(pid, f"[Nmap] Error: {e}")


def _shodan_host(pid, ip):
    if not SHODAN_KEY: return
    _log(pid, f"[Shodan] Datos de host {ip}...")
    try:
        r = SESSION.get(f"https://api.shodan.io/shodan/host/{ip}",
                        params={"key": SHODAN_KEY}, timeout=20)
        if r.status_code == 404:
            _log(pid, f"[Shodan] {ip} no indexado"); return
        if r.status_code != 200: return
        d         = r.json()
        vulns     = d.get("vulns", {})
        org       = d.get("org", "—")
        country   = d.get("country_name", "")
        os_       = d.get("os") or "desconocido"
        hostnames = d.get("hostnames", [])
        isp       = d.get("isp", "—")
        asn       = d.get("asn", "—")
        tags      = d.get("tags", [])
        cloud     = d.get("cloud", {})
        ports_raw = d.get("data", [])

        # Puertos indexados con producto y versión
        port_lines = []
        for item in ports_raw[:15]:
            p         = item.get("port", "")
            product   = item.get("product", "")
            version   = item.get("version", "")
            transport = item.get("transport", "tcp")
            banner    = (item.get("data") or "").split("\n")[0][:80]
            if p:
                line = f"  • {p}/{transport}"
                if product: line += f" — {product}"
                if version: line += f" {version}"
                if banner and not product: line += f" ({banner})"
                port_lines.append(line)

        cloud_str = ""
        if cloud:
            parts = [cloud.get("provider",""), cloud.get("region",""), cloud.get("service","")]
            joined = " / ".join(p for p in parts if p)
            if joined: cloud_str = f"\nCloud: {joined}"

        tags_str  = f"\nEtiquetas: {', '.join(tags)}" if tags else ""
        ports_str = ("\n\nPuertos indexados por Shodan:\n" + "\n".join(port_lines)) if port_lines else ""

        _finding(pid, ip, "shodan", "info",
                 f"Perfil de host {ip} en Shodan",
                 f"Organización: {org}\nISP: {isp}\nASN: {asn}\nPaís: {country}\n"
                 f"Sistema operativo: {os_}\nHostnames: {', '.join(hostnames[:5]) or '—'}\n"
                 f"CVEs conocidos: {len(vulns)}"
                 f"{cloud_str}{tags_str}{ports_str}",
                 "Verifica que esta IP pertenezca a la organización y que los datos sean correctos.")

        for cve, info in (vulns.items() if isinstance(vulns, dict) else {}.items()):
            if not isinstance(info, dict):
                continue
            cvss2   = float(info.get("cvss",  0) or 0)
            cvss3   = float(info.get("cvss3", 0) or 0)
            kev     = bool(info.get("kev", False))
            epss    = float(info.get("epss", 0) or 0)
            summary = info.get("summary", "")[:300]

            # Usar CVSS v3 si disponible, si no v2
            if cvss3 > 0:
                score, cvss_ver = cvss3, "v3.1"
            else:
                score, cvss_ver = cvss2, "v2.0"

            sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
            sev_label = "CRÍTICA" if score >= 9 else "ALTA" if score >= 7 else "MEDIA" if score >= 4 else "BAJA"

            kev_note = "\n⚠ KEV: Esta vulnerabilidad está siendo explotada activamente (CISA KEV)." if kev else ""
            epss_note = f"\nEPSS: {epss:.1%} probabilidad de explotación en los próximos 30 días." if epss > 0 else ""

            risk_word = "crítico" if score >= 9 else "alto" if score >= 7 else "moderado"
            cve_detail_parts = [
                f"La vulnerabilidad {cve} ha sido identificada en el host {ip}. "
                f"Su puntuación CVSS {cvss_ver} es {score}/10 ({sev_label}), "
                f"lo que indica un riesgo {risk_word}."
            ]
            if summary:
                cve_detail_parts.append(f"\n\n{summary}")
            if kev:
                cve_detail_parts.append(
                    "\n\nEsta vulnerabilidad figura en el catálogo KEV (Known Exploited Vulnerabilities) "
                    "de CISA, lo que confirma que está siendo explotada activamente por actores de amenaza "
                    "en entornos reales. La prioridad de parcheo es máxima."
                )
            if epss > 0:
                cve_detail_parts.append(
                    f"\n\nÍndice EPSS: {epss:.1%} — probabilidad estimada de explotación en los próximos 30 días."
                )
            _finding(pid, ip, "shodan", sev,
                     f"{cve} — CVSS {cvss_ver} {score} ({sev_label}){' [KEV]' if kev else ''}",
                     "".join(cve_detail_parts),
                     f"Aplica el parche de seguridad para {cve} con carácter urgente (CVSS {score}/10)."
                     f"{' La explotación activa confirmada en el catálogo KEV hace imprescindible la acción inmediata.' if kev else ''}"
                     f" Verifica el vector de ataque y si el servicio afectado puede desconectarse temporalmente.")
    except Exception as e:
        _err(pid, f"[Shodan] Error host: {e}")


def _internetdb(pid, ip):
    _log(pid, f"[InternetDB] Exposición rápida de {ip}...")
    try:
        r = SESSION.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code != 200: return
        d = r.json()
        risky = [p for p in d.get("ports", []) if p in RISKY_PORTS]
        for p in risky:
            pinfo    = PORT_INFO.get(p, ("", "high", ""))
            svc_name = pinfo[0] or f"puerto {p}"
            port_sev = pinfo[1] if pinfo else "high"
            port_ctx = pinfo[2] if pinfo and pinfo[2] else (
                f"El puerto {p} ({svc_name}) está expuesto en {ip} y ha sido indexado por Shodan InternetDB."
            )
            _finding(pid, ip, "exposure", port_sev,
                     f"Puerto {p} ({svc_name}) expuesto en {ip} — confirmado por Shodan",
                     port_ctx,
                     f"Aplica reglas de firewall para restringir el acceso al puerto {p} desde Internet. "
                     f"Si el servicio no es estrictamente necesario de forma pública, ciérralo o limítalo "
                     f"a rangos IP de confianza mediante listas de control de acceso.")
        for cve in d.get("vulns", []):
            _finding(pid, ip, "exposure", "high",
                     f"{cve} activo en {ip} — confirmado por Shodan InternetDB",
                     f"Shodan InternetDB ha indexado la vulnerabilidad {cve} como activa en el host {ip}. "
                     f"Esto indica que el servicio afectado está expuesto a Internet y que la versión "
                     f"vulnerable es detectable de forma remota por escáneres automatizados. "
                     f"Los actores de amenaza utilizan estos índices públicos para localizar objetivos de forma masiva.",
                     f"Aplica el parche correspondiente a {cve} de inmediato. "
                     f"Mientras el parche no esté disponible, restringe el acceso al servicio afectado "
                     f"mediante firewall o deshabilítalo si no es necesario.")
    except Exception as e:
        _err(pid, f"[InternetDB] Error: {e}")


def _virustotal_ip(pid, ip):
    if not VT_KEY: return
    _log(pid, f"[VirusTotal] Reputación de {ip}...")
    try:
        r = SESSION.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": VT_KEY}, timeout=20)
        if r.status_code != 200: return
        attrs     = r.json().get("data", {}).get("attributes", {})
        stats     = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total     = sum(stats.values()) or 1
        country   = attrs.get("country", "—")
        asn       = attrs.get("asn", "—")
        owner     = attrs.get("as_owner", "—")

        if malicious > 0:
            _finding(pid, ip, "virustotal", "high",
                     f"{ip} reportada como maliciosa por {malicious}/{total} motores AV",
                     f"La dirección IP {ip} ({country}, ASN {asn} — {owner}) ha sido reportada como "
                     f"maliciosa por {malicious} de {total} motores de reputación analizados por VirusTotal."
                     f"\n\nEsta IP puede estar comprometida y actuando como nodo de una botnet, "
                     f"infraestructura de comando y control (C2), o puede haber sido utilizada para "
                     f"realizar escaneos masivos, ataques de fuerza bruta o distribución de malware. "
                     f"La presencia en listas negras de seguridad confirma actividad maliciosa documentada.",
                     f"Investiga el origen y uso de la IP {ip}. Si pertenece a la organización, "
                     f"comprueba si ha sido comprometida y aíslala para análisis forense. "
                     f"Si es una IP de terceros, bloquéala en el firewall perimetral y en las reglas de IDS/IPS.")
        else:
            _finding(pid, ip, "virustotal", "info",
                     f"{ip} sin detecciones en VirusTotal ({total} motores)",
                     f"La dirección IP {ip} ({country}, ASN {asn} — {owner}) no presenta alertas de "
                     f"seguridad en ninguno de los {total} motores de reputación de VirusTotal. "
                     f"La IP no figura en listas negras conocidas en el momento del análisis.",
                     "Monitoriza periódicamente la reputación de esta IP. "
                     "La ausencia de alertas actuales no garantiza que no aparezcan en el futuro.")
    except Exception as e:
        _err(pid, f"[VirusTotal] Error IP: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# FASE 3 — Emails
# ══════════════════════════════════════════════════════════════════════════════

def _blackbird(pid, email):
    _log(pid, f"[Blackbird] Presencia de {email} en plataformas...")
    usernames = _usernames_from_email(email)
    try:
        proc = subprocess.run(
            ["blackbird", "-u", email.split("@")[0], "--no-update"],
            capture_output=True, text=True, timeout=120
        )
        output = proc.stdout + proc.stderr
        found  = re.findall(r'\[✓\]\s+(.+)', output)
        if found:
            _finding(pid, email, "blackbird", "medium",
                     f"Presencia de '{email.split('@')[0]}' en {len(found)} plataformas online",
                     f"Plataformas donde se encontró el username:\n" +
                     "\n".join(f"  • {p}" for p in found[:20]) +
                     f"\n\nEsta presencia pública puede usarse para OSINT del empleado "
                     f"(ingeniería social, spear phishing, acceso a cuentas corporativas).",
                     "Evalúa si estas cuentas deben existir públicamente. "
                     "Forma a los empleados sobre el riesgo de usar el email/username corporativo en servicios externos.")
            _log(pid, f"[Blackbird] {len(found)} plataformas para {email}")
        else:
            _log(pid, f"[Blackbird] Sin resultados para {email}")
    except FileNotFoundError:
        _log(pid, "[Blackbird] No instalado, omitiendo")
    except Exception as e:
        _err(pid, f"[Blackbird] Error: {e}")
    return usernames


# ══════════════════════════════════════════════════════════════════════════════
# FASE 4 — Usernames
# ══════════════════════════════════════════════════════════════════════════════

def _sherlock(pid, username):
    _log(pid, f"[Sherlock] Buscando '{username}' en redes sociales...")
    try:
        proc = subprocess.run(
            ["sherlock", username, "--timeout", "10", "--print-found"],
            capture_output=True, text=True, timeout=120
        )
        found = re.findall(r'\[\+\]\s+(https?://\S+)', proc.stdout)
        if found:
            _finding(pid, username, "sherlock", "medium",
                     f"Username '{username}' encontrado en {len(found)} plataformas",
                     f"Perfiles encontrados:\n" + "\n".join(f"  • {u}" for u in found[:20]) +
                     f"\n\nLa presencia de este username en plataformas públicas permite "
                     f"construir un perfil del empleado para ingeniería social.",
                     "Revisa si estas cuentas pertenecen a empleados y si contienen información sensible.")
            _log(pid, f"[Sherlock] {len(found)} perfiles para '{username}'")
        else:
            _log(pid, f"[Sherlock] Sin perfiles para '{username}'")
    except FileNotFoundError:
        _log(pid, "[Sherlock] No instalado, omitiendo")
    except Exception as e:
        _err(pid, f"[Sherlock] Error: {e}")


def _maigret(pid, username):
    _log(pid, f"[Maigret] OSINT de username '{username}'...")
    try:
        proc = subprocess.run(
            ["maigret", username, "--no-color", "-a", "--timeout", "10", "--retries", "1"],
            capture_output=True, text=True, timeout=180
        )
        found = re.findall(r'\[\+\]\s+\w+:\s+(https?://\S+)', proc.stdout)
        if found:
            _finding(pid, username, "maigret", "medium",
                     f"Maigret: '{username}' en {len(found)} sitios",
                     f"Sitios detectados:\n" + "\n".join(f"  • {u}" for u in found[:20]) +
                     f"\n\nMaigret usa análisis avanzado para correlacionar identidades online.",
                     "Analiza los perfiles encontrados — pueden revelar datos personales o profesionales.")
            _log(pid, f"[Maigret] {len(found)} sitios para '{username}'")
        else:
            _log(pid, f"[Maigret] Sin resultados para '{username}'")
    except FileNotFoundError:
        _log(pid, "[Maigret] No instalado, omitiendo")
    except Exception as e:
        _err(pid, f"[Maigret] Error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# VARIANTES DE DOMINIO
# ══════════════════════════════════════════════════════════════════════════════

_COMMON_TLDS = ['.com', '.es', '.org', '.net', '.io', '.eu', '.biz', '.info', '.co', '.online', '.app', '.tech']

def _domain_variants(pid, domain):
    """Busca variantes del dominio con diferentes TLDs — typosquatting o infraestructura relacionada."""
    parts = domain.split('.')
    if len(parts) < 2:
        return []

    base        = parts[-2]   # empresa de empresa.com / sub.empresa.com
    current_tld = '.' + parts[-1]

    _log(pid, f"[Variantes] Buscando variantes de '{base}' con diferentes TLDs...")
    found = []
    for tld in _COMMON_TLDS:
        if tld == current_tld:
            continue
        variant = base + tld
        try:
            infos   = socket.getaddrinfo(variant, None, socket.AF_INET)
            resolved = list(set(info[4][0] for info in infos if _is_public(info[4][0])))
            if resolved:
                found.append((variant, resolved))
        except Exception:
            pass

    if found:
        lines = [f"  • {v} → {', '.join(ips)}" for v, ips in found]
        _finding(pid, domain, "variants", "medium",
                 f"{len(found)} variante{'s' if len(found) != 1 else ''} de dominio activa{'s' if len(found) != 1 else ''}: "
                 f"{', '.join(v for v, _ in found)}",
                 f"Variantes del dominio '{domain}' que resuelven a IPs activas:\n" +
                 "\n".join(lines) +
                 "\n\nPueden ser dominios legítimos adicionales de la organización "
                 "o dominios de typosquatting/phishing que suplantan su identidad.",
                 "Verifica si estas variantes pertenecen a la organización. "
                 "Si no son tuyas, monitoriza si se usan para phishing. "
                 "Considera registrar las variantes clave (.es, .com, .org) para proteger la marca.")
        _log(pid, f"[Variantes] {len(found)} variantes activas: {', '.join(v for v, _ in found)}")
    else:
        _log(pid, f"[Variantes] Sin variantes activas para '{base}'")

    return found


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def _run(pid, seeds):
    visited_domains   = set()
    visited_ips       = set()
    visited_emails    = set()
    visited_usernames = set()
    ip_queue          = []
    email_queue       = []
    username_queue    = []

    try:
        for seed in seeds:
            seed  = seed.strip().lower()
            atype = _asset_type(seed)

            if atype == "domain" and seed not in visited_domains:
                visited_domains.add(seed)
                _push(pid, {"type": "asset_start", "asset": seed, "asset_type": "domain"})

                new_ips = set()
                username_queue.extend(_whois(pid, seed))
                new_ips.update(_dns(pid, seed))

                all_subs = set(_subfinder(pid, seed)) | set(_crtsh(pid, seed))
                for sub in list(all_subs)[:10]:
                    if sub not in visited_domains:
                        visited_domains.add(sub)
                        new_ips.update(_dns_quick(pid, sub))

                new_ips.update(_shodan_domain(pid, seed))
                new_ips.update(_virustotal_domain(pid, seed) or [])
                new_ips.update(_urlscan(pid, seed) or [])
                _intelx(pid, seed)
                _intelx(pid, f"@{seed}")   # credenciales/emails del dominio filtrados
                _domain_variants(pid, seed)

                for em in _harvester(pid, seed):
                    if em not in visited_emails:
                        email_queue.append(em)

                for ip in new_ips:
                    if _is_public(ip) and ip not in visited_ips:
                        ip_queue.append(ip)

                _push(pid, {"type": "asset_done", "asset": seed})

            elif atype == "ip" and seed not in visited_ips:
                ip_queue.append(seed)
            elif atype == "email" and seed not in visited_emails:
                email_queue.append(seed)

        # Fase 2: IPs
        unique_ips = list(dict.fromkeys(ip_queue))
        if unique_ips:
            _log(pid, f"\n▶ Fase 2 — Analizando {len(unique_ips)} IPs...")
        for ip in unique_ips:
            if ip in visited_ips: continue
            visited_ips.add(ip)
            _push(pid, {"type": "asset_start", "asset": ip, "asset_type": "ip"})
            _nmap(pid, ip)
            _shodan_host(pid, ip)
            _internetdb(pid, ip)
            _virustotal_ip(pid, ip)
            _push(pid, {"type": "asset_done", "asset": ip})

        # Fase 3: Emails
        unique_emails = list(dict.fromkeys(email_queue))
        if unique_emails:
            _log(pid, f"\n▶ Fase 3 — Analizando {len(unique_emails)} emails...")
        for em in unique_emails:
            if em in visited_emails: continue
            visited_emails.add(em)
            _push(pid, {"type": "asset_start", "asset": em, "asset_type": "email"})
            _intelx(pid, em)
            username_queue.extend(_blackbird(pid, em))
            _push(pid, {"type": "asset_done", "asset": em})

        # Fase 4: Usernames
        unique_users = list(dict.fromkeys(username_queue))
        if unique_users:
            _log(pid, f"\n▶ Fase 4 — Analizando {len(unique_users)} usernames...")
        for uname in unique_users:
            if uname in visited_usernames or len(uname) < 3: continue
            visited_usernames.add(uname)
            _push(pid, {"type": "asset_start", "asset": uname, "asset_type": "username"})
            _sherlock(pid, uname)
            _maigret(pid, uname)
            _push(pid, {"type": "asset_done", "asset": uname})

    except Exception as e:
        _err(pid, f"[Pipeline] Error: {e}")
    finally:
        findings = get_findings(pid)
        total    = len(findings)
        score    = calculate_score(findings)
        lbl, _   = score_label(score)
        _log(pid, f"\n✓ Análisis completado — {total} hallazgos. Score de exposición: {score}/100 ({lbl})")
        _push(pid, {"type": "pipeline_complete", "score": score, "score_label": lbl})
        with _lock:
            if pid in _pipelines:
                _pipelines[pid]["status"] = "done"
                _pipelines[pid]["score"]  = score
                # Consolidar todos los activos visitados
                _pipelines[pid]["assets"] = list(
                    visited_domains | visited_ips | visited_emails | visited_usernames
                )
