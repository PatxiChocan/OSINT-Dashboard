import subprocess
import shlex
import threading
import queue
import re
import time

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
    "timeout",
}

BINARY_PATHS = {
    "whois": "/usr/bin/whois",
    "whatweb": "/usr/bin/whatweb",
    "dnsrecon": "/usr/bin/dnsrecon",
    "timeout": "/usr/bin/timeout",
    "traceroute": "/usr/sbin/traceroute",
    "nmap": "/usr/bin/nmap",
    "nikto": "/usr/bin/nikto",
    "sslscan": "/usr/bin/sslscan",
    "sslyze": "/usr/bin/sslyze",
    "wafw00f": "/usr/bin/wafw00f",
    "enum4linux": "/usr/bin/enum4linux",
    "smbclient": "/usr/bin/smbclient",
    "ike-scan": "/usr/bin/ike-scan",
    "amass": "/usr/bin/amass",
    "katana": "/usr/bin/katana",
    "theharvester": "/usr/bin/theHarvester",
    "theHarvester": "/usr/bin/theHarvester",
}

MAX_PROCESSES = 4
PROCESS_SEMAPHORE = threading.Semaphore(MAX_PROCESSES)
COMMAND_TIMEOUT = 300

ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

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

            parts = shlex.split(cmd)
            binary = parts[0].split("/")[-1]
            binary_lower = binary.lower()

            if binary in BINARY_PATHS:
                parts[0] = BINARY_PATHS[binary]
            elif binary_lower in BINARY_PATHS:
                parts[0] = BINARY_PATHS[binary_lower]

            process = subprocess.Popen(
                parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            with ACTIVE_LOCK:
                ACTIVE_PROCESSES[request_id] = process

            q = queue.Queue()
            process_start = time.time()

            def read_stream(stream, stream_type="stdout"):
                try:
                    for line in iter(stream.readline, ''):
                        clean_line = ANSI_ESCAPE.sub('', line).rstrip()
                        if clean_line:
                            q.put({
                                "type": "line",
                                "stream": stream_type,
                                "message": clean_line,
                                "request_id": request_id
                            })
                except Exception as e:
                    q.put({
                        "type": "error",
                        "message": f"Error leyendo {stream_type}: {e}",
                        "request_id": request_id
                    })
                finally:
                    q.put({
                        "type": "_stream_end",
                        "stream": stream_type,
                        "request_id": request_id
                    })

            t_out = threading.Thread(
                target=read_stream,
                args=(process.stdout, "stdout"),
                daemon=True
            )
            t_err = threading.Thread(
                target=read_stream,
                args=(process.stderr, "stderr"),
                daemon=True
            )
            t_out.start()
            t_err.start()

            finished_streams = 0

            while True:
                # Timeout duro del proceso
                if process.poll() is None and (time.time() - process_start) > COMMAND_TIMEOUT:
                    process.kill()
                    yield {
                        "type": "error",
                        "message": "Timeout: el proceso tardó demasiado",
                        "request_id": request_id
                    }
                    break

                try:
                    item = q.get(timeout=0.2)

                    if item["type"] == "_stream_end":
                        finished_streams += 1
                    else:
                        yield item

                except queue.Empty:
                    pass

                # Si el proceso terminó, vaciamos cola y cerramos
                if process.poll() is not None:
                    while True:
                        try:
                            item = q.get_nowait()
                            if item["type"] == "_stream_end":
                                finished_streams += 1
                            else:
                                yield item
                        except queue.Empty:
                            break
                    break

            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                yield {
                    "type": "error",
                    "message": "Timeout: el proceso tardó demasiado en cerrarse",
                    "request_id": request_id
                }

            if process.stdout:
                try:
                    process.stdout.close()
                except Exception:
                    pass

            if process.stderr:
                try:
                    process.stderr.close()
                except Exception:
                    pass

            if process.returncode not in (0, None, -9):
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