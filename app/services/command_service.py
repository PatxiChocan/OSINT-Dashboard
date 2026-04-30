import subprocess
import shlex
import threading
import queue
import re
import time
import json
import os
import uuid
import signal


ALLOWED_BINARIES = {
    "script",
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
    "script": "/usr/bin/script",
    "amass": "/usr/local/bin/amass",
    "katana": "/home/kali/go/bin/katana",
    "theharvester": "/usr/bin/theHarvester",
    "theHarvester": "/usr/bin/theHarvester",
    "gitleaks": "/home/kali/.local/bin/gitleaks",
    "wayback_machine_downloader": "/home/kali/.local/bin/wayback_machine_downloader",
}

MAX_PROCESSES = 4
PROCESS_SEMAPHORE = threading.Semaphore(MAX_PROCESSES)

DEFAULT_COMMAND_TIMEOUT = 120
TOOL_TIMEOUTS = {
    "amass": 600,
    "katana": 300,
    "wayback_machine_downloader": 120,
    "default": DEFAULT_COMMAND_TIMEOUT,
}

ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
SAFE_CMD_REGEX = re.compile(r'^[a-zA-Z0-9_\-./:=,@ "]+$')

ACTIVE_PROCESSES = {}
ACTIVE_LOCK = threading.Lock()

TMP_DIR = "/tmp/aletheia"
DOWNLOADS_DIR = "/home/kali/aletheia-downloads"
os.makedirs(TMP_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)


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


def _extract_inner_parts(parts):
    """
    Si el comando va envuelto con script -c "...", devuelve las partes del comando interno.
    Si no, devuelve las partes originales.
    """
    if not parts:
        return parts

    first = parts[0].split("/")[-1].lower()
    if first == "script" and "-c" in parts:
        try:
            c_idx = parts.index("-c")
            inner_cmd = parts[c_idx + 1]
            return shlex.split(inner_cmd)
        except (ValueError, IndexError):
            return parts
        except Exception:
            return parts

    return parts


def _resolve_binary_path(binary_name: str) -> str:
    if not binary_name:
        return binary_name

    if binary_name in BINARY_PATHS:
        return BINARY_PATHS[binary_name]

    lower_name = binary_name.lower()
    if lower_name in BINARY_PATHS:
        return BINARY_PATHS[lower_name]

    return binary_name


def _detect_tool(parts):
    if not parts:
        return None

    effective_parts = _extract_inner_parts(parts)
    if not effective_parts:
        return None

    tool = effective_parts[0].split("/")[-1].lower()

    aliases = {
        "theharvester": "theharvester",
        "amass": "amass",
        "dnsrecon": "dnsrecon",
        "nmap": "nmap",
        "wayback_machine_downloader": "wayback_machine_downloader",
    }

    return aliases.get(tool)


def _already_has_flag(parts, flag):
    return any(flag == p or p.startswith(flag) for p in parts)


def _get_command_timeout(parts):
    tool = _detect_tool(parts)
    if tool and tool in TOOL_TIMEOUTS:
        return TOOL_TIMEOUTS[tool]
    return TOOL_TIMEOUTS["default"]


def _is_safe_output_path(path: str) -> bool:
    try:
        real = os.path.realpath(path)
        return (
            real.startswith(os.path.realpath(TMP_DIR) + os.sep) or
            real.startswith(os.path.realpath(DOWNLOADS_DIR) + os.sep)
        )
    except Exception:
        return False


def _validate_output_flags(parts: list) -> tuple[bool, str]:
    """
    Bloquea flags de escritura que apunten fuera de TMP_DIR
    para evitar sobrescritura de archivos arbitrarios.
    """
    OUTPUT_FLAGS = {"-oN", "-oJ", "-oX", "-oG", "-oA", "-oS", "-f", "-j", "-d"}
    for i, part in enumerate(parts):
        if part in OUTPUT_FLAGS and i + 1 < len(parts):
            target_path = parts[i + 1]
            if not _is_safe_output_path(target_path):
                return False, f"Flag {part} apunta a una ruta no permitida: {target_path}"
    return True, ""


def setup_structured_output(parts, request_id):
    if not parts:
        return parts, None

    tool = _detect_tool(parts)
    if not tool:
        return parts, None

    json_path = os.path.join(TMP_DIR, f"{request_id}.json")
    base = os.path.join(TMP_DIR, request_id)

    is_script_wrapped = parts[0].split("/")[-1].lower() == "script" and "-c" in parts

    if is_script_wrapped:
        try:
            c_idx = parts.index("-c")
            inner = parts[c_idx + 1]
        except (ValueError, IndexError):
            return parts, None

        flag_map = {
            "theharvester": ("-f", f"-f {base}"),
            "dnsrecon": ("-j", f"-j {json_path}"),
            "nmap": ("-oJ", f"-oJ {json_path}"),
        }

        check_flag, inject = flag_map.get(tool, (None, None))
        if not check_flag:
            return parts, None

        if check_flag in inner:
            return parts, json_path

        new_parts = list(parts)
        new_parts[c_idx + 1] = inner + f" {inject}"
        return new_parts, json_path

    flag_map = {
        "theharvester": ("-f", ["-f", base]),
        "dnsrecon": ("-j", ["-j", json_path]),
        "nmap": ("-oJ", ["-oJ", json_path]),
    }

    check_flag, inject = flag_map.get(tool, (None, None))
    if not check_flag:
        return parts, None

    if _already_has_flag(parts, check_flag):
        return parts, json_path

    return list(parts) + inject, json_path


def parse_structured_json(binary, json_path):
    if not json_path or not os.path.exists(json_path):
        return None

    try:
        with open(json_path, "r", errors="replace") as fh:
            raw = fh.read().strip()
        if not raw:
            return None
    except Exception:
        return None

    binary = binary.lower()

    if binary == "theharvester":
        try:
            data = json.loads(raw)
            hosts_raw = data.get("hosts", [])

            _hex_seg = re.compile(r'^[0-9][A-F][a-z]')

            def _clean_host(raw_host):
                raw_host = raw_host.strip()
                if ":" in raw_host:
                    host, ip = raw_host.split(":", 1)
                    host, ip = host.strip(), ip.strip()
                else:
                    host, ip = raw_host, None

                first_seg = host.lstrip('*.').split('.')[0]
                if _hex_seg.match(first_seg):
                    return None, None

                return host, ip

            hosts_only = []
            ips_from_hosts = []

            for h in hosts_raw:
                host, ip = _clean_host(h)
                if host:
                    hosts_only.append(host)
                if ip:
                    ips_from_hosts.append(ip)

            explicit_ips = data.get("ips", [])
            all_ips = list(dict.fromkeys(explicit_ips + ips_from_hosts))

            return {
                "tool": "theharvester",
                "emails": data.get("emails", []),
                "ips": all_ips,
                "hosts": hosts_only,
                "hosts_with_ip": hosts_raw,
                "interesting_urls": data.get("interesting_urls", []),
                "asns": [str(a) for a in data.get("asns", [])],
            }
        except Exception:
            return None

    if binary == "dnsrecon":
        try:
            records = json.loads(raw)
            by_type = {}

            for r in records:
                t = r.get("type", "OTHER").upper()
                by_type.setdefault(t, [])

                if t == "A":
                    by_type[t].append(f"{r.get('name', '')} → {r.get('address', '')}")
                elif t == "AAAA":
                    by_type[t].append(f"{r.get('name', '')} → {r.get('address', '')}")
                elif t == "MX":
                    by_type[t].append(
                        f"{r.get('name', '')} (pri {r.get('preference', '')}) → {r.get('exchange', '')}"
                    )
                elif t == "NS":
                    by_type[t].append(f"{r.get('target', '')}")
                elif t == "TXT":
                    by_type[t].append(f"{r.get('name', '')} → {r.get('strings', '')}")
                elif t == "SOA":
                    by_type[t].append(f"mname={r.get('mname', '')} rname={r.get('rname', '')}")
                elif t == "CNAME":
                    by_type[t].append(f"{r.get('name', '')} → {r.get('target', '')}")
                elif t == "SRV":
                    by_type[t].append(
                        f"{r.get('name', '')} → {r.get('target', '')}:{r.get('port', '')}"
                    )
                else:
                    by_type[t].append(str(r))

            return {"tool": "dnsrecon", "records": by_type}
        except Exception:
            return None

    if binary == "nmap":
        try:
            data = json.loads(raw)
            hosts_raw = data.get("nmaprun", {}).get("host", [])
            if isinstance(hosts_raw, dict):
                hosts_raw = [hosts_raw]

            ports_open = []
            ports_filtered = []
            ips = []
            os_detected = []

            for host in hosts_raw:
                addrs = host.get("address", [])
                if isinstance(addrs, dict):
                    addrs = [addrs]

                for a in addrs:
                    if a.get("addrtype") in ("ipv4", "ipv6"):
                        ips.append(a.get("addr", ""))

                ports_wrap = host.get("ports", {})
                ports_list = ports_wrap.get("port", [])
                if isinstance(ports_list, dict):
                    ports_list = [ports_list]

                for p in ports_list:
                    state = p.get("state", {}).get("state", "")
                    portid = p.get("portid", "")
                    proto = p.get("protocol", "tcp")
                    svc = p.get("service", {}).get("name", "")
                    ver = p.get("service", {}).get("product", "")
                    extra = p.get("service", {}).get("version", "")
                    full_ver = " ".join(filter(None, [ver, extra]))

                    entry = {
                        "port": portid,
                        "proto": proto,
                        "state": state,
                        "service": svc,
                        "version": full_ver,
                    }

                    if state == "open":
                        ports_open.append(entry)
                    elif state in ("filtered", "closed"):
                        ports_filtered.append(entry)

                os_matches = host.get("os", {}).get("osmatch", [])
                if isinstance(os_matches, dict):
                    os_matches = [os_matches]

                for om in os_matches[:1]:
                    os_detected.append(f"{om.get('name', '')} ({om.get('accuracy', '')}%)")

            return {
                "tool": "nmap",
                "ips": ips,
                "ports_open": ports_open,
                "ports_filtered": ports_filtered,
                "os": os_detected,
            }
        except Exception:
            return None

    if binary == "amass":
        try:
            subdomains = []
            ips = []

            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue

                obj = json.loads(line)
                name = obj.get("name", "")
                if name:
                    subdomains.append(name)

                for addr in obj.get("addresses", []):
                    ip = addr.get("ip", "")
                    if ip:
                        ips.append(ip)

            return {
                "tool": "amass",
                "subdomains": list(dict.fromkeys(subdomains)),
                "ips": list(dict.fromkeys(ips)),
            }
        except Exception:
            return None

    return None


def stop_command(request_id: str) -> bool:
    with ACTIVE_LOCK:
        process = ACTIVE_PROCESSES.get(request_id)

    if not process:
        return False

    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception:
        pass

    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except Exception:
            pass

    return True


def run_command(cmd: str, request_id: str):
    with PROCESS_SEMAPHORE:
        process = None

        try:
            yield {"type": "start", "message": cmd, "request_id": request_id}

            parts = shlex.split(cmd)
            if not parts:
                yield {
                    "type": "error",
                    "message": "Comando vacío",
                    "request_id": request_id
                }
                yield {"type": "done", "request_id": request_id}
                return

            binary = parts[0].split("/")[-1]
            parts[0] = _resolve_binary_path(binary)

            json_path = None
            try:
                parts, json_path = setup_structured_output(parts, request_id)
            except Exception:
                pass

            path_ok, path_err = _validate_output_flags(parts)
            if not path_ok:
                yield {"type": "error", "message": path_err, "request_id": request_id}
                yield {"type": "done", "request_id": request_id}
                return

            effective_timeout = _get_command_timeout(parts)

            process = subprocess.Popen(
                parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
            )

            with ACTIVE_LOCK:
                ACTIVE_PROCESSES[request_id] = process

            q = queue.Queue()
            process_start = time.time()

            def read_stream(stream, stream_type="stdout"):
                try:
                    for line in iter(stream.readline, ''):
                        try:
                            clean_line = ANSI_ESCAPE.sub('', line).rstrip()
                        except Exception:
                            clean_line = repr(line).strip("'")

                        if clean_line:
                            q.put({
                                "type": "line",
                                "stream": stream_type,
                                "message": clean_line,
                                "request_id": request_id
                            })
                except Exception as e:
                    q.put({
                        "type": "line",
                        "stream": "stderr",
                        "message": f"[read error: {e}]",
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
            timed_out = False

            # last_activity se resetea con cada línea de output (idle timeout)
            last_activity = time.time()
            last_heartbeat = time.time()
            heartbeat_interval = 15  # segundos

            while True:
                if process.poll() is None and (time.time() - last_activity) > effective_timeout:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except Exception:
                        process.kill()
                    timed_out = True

                    yield {
                        "type": "error",
                        "message": f"Timeout: sin actividad durante {effective_timeout}s",
                        "request_id": request_id
                    }

                    t_out.join(timeout=2)
                    t_err.join(timeout=2)

                    while True:
                        try:
                            item = q.get_nowait()
                            if item["type"] != "_stream_end":
                                yield item
                        except queue.Empty:
                            break
                    break

                try:
                    item = q.get(timeout=0.2)
                    if item["type"] == "_stream_end":
                        finished_streams += 1
                        if finished_streams >= 2:
                            break
                    else:
                        yield item
                        last_activity = time.time()
                        last_heartbeat = time.time()
                except queue.Empty:
                    if process.poll() is None and (time.time() - last_heartbeat) >= heartbeat_interval:
                        yield {
                            "type": "heartbeat",
                            "message": "keepalive",
                            "request_id": request_id
                        }
                        last_heartbeat = time.time()

                if process.poll() is not None:
                    t_out.join(timeout=3)
                    t_err.join(timeout=3)

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

            if not timed_out:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()

            for stream in (process.stdout, process.stderr):
                if stream:
                    try:
                        stream.close()
                    except Exception:
                        pass

            rc = process.returncode
            if rc not in (0, None, -9):
                yield {
                    "type": "exit",
                    "message": str(rc),
                    "request_id": request_id
                }

            if json_path:
                binary_name = _detect_tool(parts) or (parts[0].split("/")[-1].lower() if parts else "")
                try:
                    structured = parse_structured_json(binary_name, json_path)
                    if structured:
                        yield {
                            "type": "structured",
                            "data": structured,
                            "request_id": request_id
                        }
                except Exception:
                    pass
                finally:
                    try:
                        os.remove(json_path)
                    except Exception:
                        pass

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
