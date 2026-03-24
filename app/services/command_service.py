import subprocess
import shlex
import threading
import queue
import re
import time
import json
import os
import tempfile
import uuid


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
    "katana": "/usr/bin/katana",
    "theharvester": "/usr/bin/theHarvester",
    "theHarvester": "/usr/bin/theHarvester",
}

MAX_PROCESSES = 4
PROCESS_SEMAPHORE = threading.Semaphore(MAX_PROCESSES)
COMMAND_TIMEOUT = 1000 

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


TMP_DIR = "/tmp/aletheia"

# Ensure tmp dir exists
os.makedirs(TMP_DIR, exist_ok=True)

# Tools that support structured JSON output and how to inject the flag
# Returns (tool_key, json_path) or (None, None)
def _detect_tool(parts):
    """Return the OSINT tool name regardless of wrappers like script/timeout."""
    cmd_str = " ".join(parts).lower()
    for tool in ("theharvester", "dnsrecon", "nmap", "amass"):
        if tool in cmd_str:
            return tool
    return None


def _already_has_flag(parts, flag):
    """Check if flag already present anywhere in the command."""
    return any(flag in p for p in parts)


def setup_structured_output(parts, request_id):
    if not parts:
        return parts, None

    tool = _detect_tool(parts)
    if not tool:
        return parts, None

    json_path = os.path.join(TMP_DIR, f"{request_id}.json")
    base      = os.path.join(TMP_DIR, request_id)

    is_script_wrapped = parts[0].split("/")[-1].lower() == "script" and "-c" in parts

    if is_script_wrapped:
        try:
            c_idx = parts.index("-c")
            inner = parts[c_idx + 1]
        except (ValueError, IndexError):
            return parts, None

        # Don't inject if flag already present in inner command
        flag_map = {
            "theharvester": ("-f", f"-f {base}"),
            "dnsrecon":     ("-j", f"-j {json_path}"),
            "nmap":         ("-oJ", f"-oJ {json_path}"),
            # "amass":      ("-json", ...) — not supported in v4.2.0
        }
        check_flag, inject = flag_map.get(tool, (None, None))
        if not check_flag:
            return parts, None
        if check_flag in inner:
            # Already has the flag — extract existing json_path if possible
            return parts, json_path
        new_parts = list(parts)
        new_parts[c_idx + 1] = inner + f" {inject}"
        return new_parts, json_path

    # Direct invocation — check if flag already present
    flag_map = {
        "theharvester": ("-f", ["-f", base]),
        "dnsrecon":     ("-j", ["-j", json_path]),
        "nmap":         ("-oJ", ["-oJ", json_path]),
        # amass -json not supported in v4.2.0
    }
    check_flag, inject = flag_map.get(tool, (None, None))
    if not check_flag:
        return parts, None
    if _already_has_flag(parts, check_flag):
        return parts, json_path
    return list(parts) + inject, json_path


def parse_structured_json(binary, json_path):
    """Read and normalise the JSON file produced by the tool."""
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

    # ── theHarvester ──────────────────────────────────────────────────────
    if binary == "theharvester":
        try:
            data = json.loads(raw)
            hosts_raw = data.get("hosts", [])

            # Hosts field format: "subdomain.example.com:1.2.3.4" or just "subdomain.example.com"
            _hex_seg = re.compile(r'^[0-9][A-F][a-z]')  # catches "2Fbrand", "3Adocs" etc. (URL-encoded path artifacts)

            def _clean_host(raw):
                """Return (host, ip) or (None, None) if invalid."""
                raw = raw.strip()
                if ":" in raw:
                    parts_h = raw.split(":", 1)
                    host, ip = parts_h[0].strip(), parts_h[1].strip()
                else:
                    host, ip = raw, None
                # Filter hex-encoded path artifacts like "2Fbrand.github.com"
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

            # Merge explicit ips field + ips extracted from hosts
            explicit_ips = data.get("ips", [])
            all_ips = list(dict.fromkeys(explicit_ips + ips_from_hosts))  # dedup preserving order

            return {
                "tool":             "theharvester",
                "emails":           data.get("emails", []),
                "ips":              all_ips,
                "hosts":            hosts_only,
                "hosts_with_ip":    hosts_raw,
                "interesting_urls": data.get("interesting_urls", []),
                "asns":             [str(a) for a in data.get("asns", [])],
            }
        except Exception:
            return None

    # ── DNSRecon ──────────────────────────────────────────────────────────
    if binary == "dnsrecon":
        try:
            records = json.loads(raw)
            by_type = {}
            for r in records:
                t = r.get("type", "OTHER").upper()
                by_type.setdefault(t, [])
                # Format nicely per record type
                if t == "A":
                    by_type[t].append(f"{r.get('name','')} → {r.get('address','')}")
                elif t == "AAAA":
                    by_type[t].append(f"{r.get('name','')} → {r.get('address','')}")
                elif t == "MX":
                    by_type[t].append(f"{r.get('name','')} (pri {r.get('preference','')}) → {r.get('exchange','')}")
                elif t == "NS":
                    by_type[t].append(f"{r.get('target','')}")
                elif t == "TXT":
                    by_type[t].append(f"{r.get('name','')} → {r.get('strings','')}")
                elif t == "SOA":
                    by_type[t].append(f"mname={r.get('mname','')} rname={r.get('rname','')}")
                elif t == "CNAME":
                    by_type[t].append(f"{r.get('name','')} → {r.get('target','')}")
                elif t == "SRV":
                    by_type[t].append(f"{r.get('name','')} → {r.get('target','')}:{r.get('port','')}")
                else:
                    by_type[t].append(str(r))
            return {"tool": "dnsrecon", "records": by_type}
        except Exception:
            return None

    # ── Nmap ──────────────────────────────────────────────────────────────
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
                # IPs
                addrs = host.get("address", [])
                if isinstance(addrs, dict):
                    addrs = [addrs]
                for a in addrs:
                    if a.get("addrtype") in ("ipv4", "ipv6"):
                        ips.append(a.get("addr", ""))
                # Ports
                ports_wrap = host.get("ports", {})
                ports_list = ports_wrap.get("port", [])
                if isinstance(ports_list, dict):
                    ports_list = [ports_list]
                for p in ports_list:
                    state = p.get("state", {}).get("state", "")
                    portid = p.get("portid", "")
                    proto  = p.get("protocol", "tcp")
                    svc    = p.get("service", {}).get("name", "")
                    ver    = p.get("service", {}).get("product", "")
                    extra  = p.get("service", {}).get("version", "")
                    full_ver = " ".join(filter(None, [ver, extra]))
                    entry = {"port": portid, "proto": proto, "state": state,
                             "service": svc, "version": full_ver}
                    if state == "open":
                        ports_open.append(entry)
                    elif state in ("filtered", "closed"):
                        ports_filtered.append(entry)
                # OS
                os_matches = host.get("os", {}).get("osmatch", [])
                if isinstance(os_matches, dict):
                    os_matches = [os_matches]
                for om in os_matches[:1]:
                    os_detected.append(f"{om.get('name','')} ({om.get('accuracy','')}%)")
            return {"tool": "nmap", "ips": ips,
                    "ports_open": ports_open, "ports_filtered": ports_filtered,
                    "os": os_detected}
        except Exception:
            return None

    # ── Amass (NDJSON) ────────────────────────────────────────────────────
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
            return {"tool": "amass",
                    "subdomains": list(dict.fromkeys(subdomains)),
                    "ips":        list(dict.fromkeys(ips))}
        except Exception:
            return None

    return None


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

            # Inject structured output flag if supported
            json_path = None
            try:
                parts, json_path = setup_structured_output(parts, request_id)
            except Exception:
                pass



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
                    # Don't propagate read errors as fatal — log as a warning line
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

            while True:
                # Hard timeout
                if process.poll() is None and (time.time() - process_start) > COMMAND_TIMEOUT:
                    process.kill()
                    timed_out = True
                    yield {
                        "type": "error",
                        "message": "Timeout: el proceso tardó demasiado",
                        "request_id": request_id
                    }
                    # Drain remaining queue items
                    t_out.join(timeout=2)
                    t_err.join(timeout=2)
                    while True:
                        try:
                            item = q.get_nowait()
                            if item["type"] not in ("_stream_end",):
                                yield item
                        except queue.Empty:
                            break
                    break

                try:
                    item = q.get(timeout=0.2)
                    if item["type"] == "_stream_end":
                        finished_streams += 1
                        # Both streams done — safe to exit loop
                        if finished_streams >= 2:
                            break
                    else:
                        yield item
                except queue.Empty:
                    pass

                # Process finished; wait for threads to flush, then drain
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

            # Emit structured JSON event if tool produced one
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