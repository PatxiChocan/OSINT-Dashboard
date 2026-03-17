import subprocess
import shlex
import threading
import queue
import re

ALLOWED_BINARIES = {
    "amass",
    "katana",
    "gitleaks",
    "wayback_machine_downloader",
    "spiderfoot",
    "theHarvester",
    "theharvester",
    "dnsrecon",
    "whois",
    "wafw00f",
    "whatweb",
    "traceroute",
    "nmap",
    "nikto",
    "sslscan",
    "sslyze",
    "recon-ng",
    "enum4linux",
    "smbclient",
    "ike-scan",
}

MAX_PROCESSES = 4
PROCESS_SEMAPHORE = threading.Semaphore(MAX_PROCESSES)
COMMAND_TIMEOUT = 300

# Ahora permite comillas para comandos como:
# katana -H "Cookie: session=PEGAR_AQUI"
SAFE_CMD_REGEX = re.compile(r'^[a-zA-Z0-9_\-./:=,@ "]+$')

ACTIVE_PROCESSES = {}
ACTIVE_LOCK = threading.Lock()


def is_valid_command(cmd: str) -> tuple[bool, str]:
    if not cmd:
        return False, "Comando vacío"

    if "OBJETIVO" in cmd:
        return False, "Debes indicar un objetivo real antes de ejecutar"

    if not SAFE_CMD_REGEX.match(cmd):
        return False, "El comando contiene caracteres no permitidos"

    try:
        parts = shlex.split(cmd)
    except ValueError:
        return False, "El comando no se pudo interpretar correctamente"

    if not parts:
        return False, "Comando vacío"

    first_word = parts[0].split("/")[-1]
    allowed_lower = {item.lower() for item in ALLOWED_BINARIES}

    if first_word.lower() not in allowed_lower:
        return False, f"Binario no permitido: {first_word}"

    return True, ""


def stop_command(request_id: str) -> bool:
    with ACTIVE_LOCK:
        process = ACTIVE_PROCESSES.get(request_id)

    if not process:
        return False

    try:
        process.kill()
        return True
    except Exception:
        return False


def run_command(cmd: str, request_id: str):
    with PROCESS_SEMAPHORE:
        process = None

        try:
            yield {"type": "start", "message": cmd, "request_id": request_id}

            process = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            with ACTIVE_LOCK:
                ACTIVE_PROCESSES[request_id] = process

            q = queue.Queue()

            def read_stream(stream, stream_type="stdout"):
                try:
                    for line in stream:
                        q.put({
                            "type": "line",
                            "stream": stream_type,
                            "message": line.rstrip(),
                            "request_id": request_id
                        })
                finally:
                    q.put({"type": "_stream_end", "request_id": request_id})

            t_out = threading.Thread(target=read_stream, args=(process.stdout, "stdout"), daemon=True)
            t_err = threading.Thread(target=read_stream, args=(process.stderr, "stderr"), daemon=True)
            t_out.start()
            t_err.start()

            finished_streams = 0

            while finished_streams < 2:
                item = q.get()
                if item["type"] == "_stream_end":
                    finished_streams += 1
                else:
                    yield item

            try:
                process.wait(timeout=COMMAND_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                yield {
                    "type": "error",
                    "message": "Timeout: el proceso tardó demasiado",
                    "request_id": request_id
                }
                yield {"type": "done", "request_id": request_id}
                return

            if process.returncode != 0:
                yield {
                    "type": "exit",
                    "message": str(process.returncode),
                    "request_id": request_id
                }

            yield {"type": "done", "request_id": request_id}

        except Exception as e:
            yield {
                "type": "error",
                "message": str(e),
                "request_id": request_id
            }
            yield {"type": "done", "request_id": request_id}

        finally:
            with ACTIVE_LOCK:
                ACTIVE_PROCESSES.pop(request_id, None)