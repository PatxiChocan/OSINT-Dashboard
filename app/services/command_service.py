import subprocess
import shlex
import json
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

SAFE_CMD_REGEX = re.compile(r"^[a-zA-Z0-9_\-./:=,@ ]+$")


def is_valid_command(cmd: str) -> tuple[bool, str]:
    if not cmd:
        return False, "Comando vacío"

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


def run_command(cmd):
    with PROCESS_SEMAPHORE:
        try:
            yield f"[START] {cmd}"

            process = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            q = queue.Queue()

            def read_stream(stream, prefix=""):
                try:
                    for line in stream:
                        q.put(prefix + line.rstrip())
                finally:
                    q.put(None)

            t_out = threading.Thread(target=read_stream, args=(process.stdout, ""))
            t_err = threading.Thread(target=read_stream, args=(process.stderr, "[stderr] "))
            t_out.daemon = True
            t_err.daemon = True
            t_out.start()
            t_err.start()

            finished_streams = 0

            while finished_streams < 2:
                item = q.get()
                if item is None:
                    finished_streams += 1
                else:
                    yield item

            try:
                process.wait(timeout=COMMAND_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                yield "[ERROR] Timeout: el proceso tardó demasiado"
                return

            if process.returncode != 0:
                yield f"[EXIT CODE] {process.returncode}"

            yield "[DONE]"

        except Exception as e:
            yield f"[ERROR] {str(e)}"