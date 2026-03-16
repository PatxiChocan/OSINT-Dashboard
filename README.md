# 🛡️ OSINT Arsenal Dashboard

> Panel web para lanzar herramientas OSINT directamente desde Kali Linux — sin terminal, sin fricción.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat-square&logo=flask&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## ✨ ¿Qué es esto?

**OSINT Arsenal Dashboard** es una interfaz web construida con Flask que permite ejecutar las herramientas OSINT más populares de Kali Linux desde el navegador. Ideal para pentesters y analistas que quieren centralizar su flujo de trabajo sin abrir múltiples terminales.

---

## 🧰 Herramientas soportadas

| Herramienta | Categoría | Descripción |
|---|---|---|
| **Amass** | Reconocimiento | Enumeración de subdominios y mapeo de red |
| **Katana** | Crawling | Rastreador web de alto rendimiento |
| **GitLeaks** | Secretos | Detección de credenciales en repositorios Git |
| **Wayback Machine Downloader** | OSINT Web | Descarga de versiones archivadas de sitios web |
| **SpiderFoot** | Automatización | Recopilación automatizada de inteligencia |
| **theHarvester** | OSINT | Recopilación de emails, dominios y hosts |
| **DNSRecon** | DNS | Enumeración y análisis de registros DNS |
| **Nmap** | Escaneo de red | Descubrimiento de hosts y servicios |
| **Nikto** | Web | Escáner de vulnerabilidades web |
| **SSLScan** | SSL/TLS | Análisis de configuración SSL/TLS |
| **SSLyze** | SSL/TLS | Auditoría avanzada de servidores SSL/TLS |

---

## ⚙️ Requisitos previos

- **Sistema operativo**: Kali Linux (recomendado) o cualquier distro con las herramientas instaladas
- **Python**: 3.8 o superior
- **Herramientas OSINT**: instaladas y disponibles en el `PATH` del sistema

Para verificar que las herramientas están disponibles:

```bash
which amass katana gitleaks nmap nikto sslscan sslyze theharvester dnsrecon spiderfoot
```

---

## 🚀 Instalación rápida (Setup)

```bash
# 1. Clonar el repositorio
git clone https://github.com/PatxiChocan/OSINT-Dashboard.git
cd OSINT-Dashboard

# 2. Crear entorno virtual
python3 -m venv venv

# 3. Activar el entorno virtual
source venv/bin/activate

# 4. Instalar dependencias
pip install -r requirements.txt

# 5. Iniciar la aplicación
python app.py
```

Luego abre tu navegador en:

```
http://127.0.0.1:5000
```

---

## 📦 Instalación manual (sin venv)

Si prefieres instalarlo directamente sin entorno virtual:

```bash
git clone https://github.com/PatxiChocan/OSINT-Dashboard.git
cd OSINT-Dashboard
pip install flask
python3 app.py
```

---

## 🗂️ Estructura del proyecto

```
OSINT-Dashboard/
├── app.py               # Servidor Flask principal
├── requirements.txt     # Dependencias Python
├── templates/           # Plantillas HTML
│   └── index.html
├── static/              # Archivos estáticos (CSS, JS)
└── README.md
```

---

## 🔒 Aviso de seguridad

> ⚠️ Esta herramienta está diseñada para uso en **entornos controlados y con autorización explícita**. El uso de herramientas OSINT sobre sistemas sin permiso puede ser ilegal. Úsala de forma responsable y ética.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Si quieres añadir soporte para nuevas herramientas o mejorar la interfaz:

1. Haz un fork del repositorio
2. Crea una rama: `git checkout -b feature/nueva-herramienta`
3. Realiza tus cambios y haz commit: `git commit -m 'feat: añadir soporte para X'`
4. Sube la rama: `git push origin feature/nueva-herramienta`
5. Abre un Pull Request

---

## 📄 Licencia

Distribuido bajo licencia MIT. Consulta el archivo `LICENSE` para más información.

---

<p align="center">Hecho con ☕ y curiosidad por <a href="https://github.com/PatxiChocan">PatxiChocan y AritzLoizate</a></p>
