import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS
import mysql.connector

# 'app' must be created BEFORE any @app.route lines below
app = Flask(__name__)
CORS(app)

# Only these commands can be run from the dashboard console
ALLOWED = {"ping", "ipconfig", "nslookup", "tracert", "arp", "netstat", "hostname"}

# --------------------------------------------------------------------------
# Scanner settings
# --------------------------------------------------------------------------

# The scanner is run as its own script, exactly as its owner wrote it.
# Put netscan.py (or netscan4_8.py) in the same folder as this file.
SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))

# Options from the scanner that can be typed in the dashboard console.
# (-y is always added by this app; -o and -h are not available here.)
ALLOWED_SCAN_FLAGS = {
    "-p", "--ports",
    "-t", "--threads",
    "--timeout",
    "--max-hosts",
    "--no-skip-unreachable",
    "--allow-public",
}

# The scanner has an --allow-public option for scanning internet addresses.
# It is switched OFF for the dashboard. Set to True only if you are authorised
# to scan those addresses and understand the risk.
ALLOW_PUBLIC_SCANS = False

SCAN_MAX_SECONDS = 30 * 60   # kill a scan that runs longer than this

PROGRESS_RE = re.compile(r"^\s*scanned \d+/\d+ checks\.\.\.")


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        port=3306,
        user="root",
        password="",
        database="netwatch_db"
    )


def find_scanner():
    for name in ("netscan.py", "netscan4_8.py"):
        path = os.path.join(SCANNER_DIR, name)
        if os.path.isfile(path):
            return path
    return None


# --------------------------------------------------------------------------
# Scan state (shared between the request handlers and the background thread)
# --------------------------------------------------------------------------

scan_lock = threading.Lock()
scan_proc = None
scan_state = {
    "status": "idle",        # idle | running | done | error | stopped
    "message": "No scan has been run yet.",
    "command": None,
    "started": None,
    "finished": None,
    "progress": "",
    "output": "",
    "stop_requested": False,
}


def local_default_target():
    """Guess the local /24 network, e.g. 192.168.1.0/24. Returns None on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))   # UDP connect sends no packets
        ip = s.getsockname()[0]
        s.close()
        if ip.startswith("127."):
            return None
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except Exception:
        return None


def guess_device_type(ports):
    """Rough guess from open ports only. These are guesses, not certainties."""
    p = set(ports)
    if not p:
        return "Unknown (no open ports)"
    if p & {9100, 515, 631}:
        return "Printer"
    if 554 in p:
        return "IP Camera / Media Device"
    if p & {3389, 135, 139}:
        return "Windows Machine"
    if 445 in p:
        return "Windows / SMB Host"
    if p & {3306, 5432, 1433, 1521, 27017}:
        return "Database Server"
    if 22 in p:
        return "Linux/Unix Host"
    if 53 in p and p & {80, 443, 8080}:
        return "Router / Gateway"
    if p & {80, 443, 8080, 8443}:
        return "Web Device (server / router / IoT)"
    return "Unclassified Host"


# --------------------------------------------------------------------------
# Reading the scanner's output
# --------------------------------------------------------------------------

def parse_scanner_output(text, port_scan):
    """
    Turn the scanner's printed results into {ip: [open ports]}.

    Port scan prints:        Host discovery prints:
        Open ports:              Hosts up (3):
          10.0.0.5: 22, 80         10.0.0.1
    """
    body = text.split("Scan completed in", 1)[-1]
    hosts = {}
    in_hosts_up = False
    for line in body.splitlines():
        if port_scan:
            m = re.match(r"^\s+(\S+): (\d+(?:, \d+)*)\s*$", line)
            if m:
                hosts[m.group(1)] = [int(x) for x in m.group(2).split(",")]
        else:
            if line.startswith("Hosts up ("):
                in_hosts_up = True
                continue
            if in_hosts_up:
                m = re.match(r"^\s+(\S+)\s*$", line)
                if m:
                    hosts[m.group(1)] = []
    return hosts


def extract_error(output):
    """Pull the scanner's own [ERROR] / [BLOCKED] message out of its output."""
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if "[ERROR]" in line or "[BLOCKED]" in line:
            return "\n".join(lines[i:i + 8]).strip()
    tail = "\n".join(lines[-5:]).strip()
    return tail or "The scanner exited with an error and printed nothing."


# --------------------------------------------------------------------------
# Saving to MySQL
# --------------------------------------------------------------------------

def _s(value):
    """MySQL connector sometimes returns bytes for SHOW COLUMNS fields."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode()
    return value


# --------------------------------------------------------------------------
# SIMULATED MONITORING DATA
# --------------------------------------------------------------------------
# The monitoring system that would measure CPU, RAM and latency for the
# network is not part of this build. The code below is a PLACEHOLDER that
# generates realistic SIMULATED values so the dashboard can show how the
# system would behave. These numbers are not real measurements.
#
# To plug in the real monitoring system later:
#   1. replace the body of collect_metrics() so it returns
#      (cpu_percent, ram_percent, latency_ms), and
#   2. set SIMULATE_LIVE_METRICS = False (or point the loop at the real feed).
# Nothing else in the project needs to change.

import math
import random

SIMULATE_LIVE_METRICS = True   # False = only record metrics when a scan runs
SIM_INTERVAL_SECONDS = 3       # how often a simulated reading is recorded
SIM_KEEP_ROWS = 200            # background readings kept (older ones are removed)


def collect_metrics():
    """Return SIMULATED (cpu_percent, ram_percent, latency_ms).

    Slow and fast waves plus a little noise make the values rise and fall
    like real load, with the occasional short spike.
    """
    t = time.time()
    cpu = 40 + 18 * math.sin(t / 25) + 8 * math.sin(t / 7) + random.uniform(-4, 4)
    ram = 55 + 7 * math.sin(t / 70) + random.uniform(-1.5, 1.5)
    latency = 25 + 10 * math.sin(t / 18) + random.uniform(-4, 4)

    if random.random() < 0.04:          # occasional CPU spike
        cpu += random.uniform(15, 30)
    if random.random() < 0.04:          # occasional latency spike
        latency += random.uniform(25, 60)

    cpu = min(98.0, max(3.0, cpu))
    ram = min(92.0, max(25.0, ram))
    latency = min(150.0, max(4.0, latency))
    return round(cpu, 1), round(ram, 1), round(latency, 1)


def _insert_simulated_reading(prune=False):
    """Record one simulated reading. scan_id is left empty because it is not
    tied to a particular scan; rows made during a scan carry a scan_id."""
    cpu, ram, latency = collect_metrics()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO system_metrics (scan_time, cpu_usage, ram_usage, latency) "
            "VALUES (%s, %s, %s, %s)",
            (datetime.now(), cpu, ram, latency),
        )
        if prune:
            # Keep the table small: only the newest background readings stay.
            # Rows that belong to a scan (scan_id set) are never removed.
            cur.execute(
                "DELETE FROM system_metrics WHERE scan_id IS NULL AND id NOT IN ("
                "SELECT id FROM (SELECT id FROM system_metrics WHERE scan_id IS NULL "
                "ORDER BY id DESC LIMIT %s) AS keep_rows)",
                (SIM_KEEP_ROWS,),
            )
        conn.commit()
        cur.close()
    finally:
        conn.close()


def simulated_metrics_loop():
    """Background loop standing in for the monitoring system's live feed."""
    count = 0
    while True:
        try:
            count += 1
            _insert_simulated_reading(prune=(count % 50 == 0))
        except Exception as e:
            print(f"[simulated metrics] skipped a reading: {e}")
        time.sleep(SIM_INTERVAL_SECONDS)


def save_results(hosts, ports_scanned):
    """
    Write scan results into discovered_devices. Existing IPs are updated,
    new IPs are inserted. Nothing is deleted.
    A host-discovery-only run (ports_scanned=False) never overwrites ports or
    device types already stored; it only refreshes scan_time on known hosts.
    Looks at the table's real columns first, so it adapts to your schema.
    """
    now = datetime.now()
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SHOW COLUMNS FROM discovered_devices")
        cols = {}
        for row in cur.fetchall():
            cols[_s(row["Field"])] = {
                "type": (_s(row["Type"]) or "").lower(),
                "null": _s(row["Null"]),
                "default": _s(row["Default"]),
                "extra": (_s(row["Extra"]) or "").lower(),
            }

        if "ip_address" not in cols:
            raise RuntimeError("discovered_devices has no ip_address column.")

        known = {"ip_address", "device_type", "open_ports", "scan_time", "scan_id"}
        required_unknown = [
            name for name, c in cols.items()
            if name not in known
            and c["null"] == "NO"
            and c["default"] is None
            and "auto_increment" not in c["extra"]
            and "generated" not in c["extra"]
        ]
        if required_unknown:
            raise RuntimeError(
                "discovered_devices has required column(s) the scanner doesn't "
                f"fill in: {', '.join(required_unknown)}. Send me the table "
                "structure so I can add them."
            )

        # One system_metrics row per scan. Its scan_id is shared by every device
        # row saved below. It must be inserted first because the foreign key on
        # discovered_devices.scan_id needs the metrics row to already exist.
        scan_id = None
        if "scan_id" in cols:
            cpu, ram, latency = collect_metrics()
            cur.execute(
                "INSERT INTO system_metrics (scan_time, cpu_usage, ram_usage, latency) "
                "VALUES (%s, %s, %s, %s)",
                (now, cpu, ram, latency),
            )
            scan_id = cur.lastrowid
            cur.execute("UPDATE system_metrics SET scan_id = %s WHERE id = %s",
                        (scan_id, scan_id))

        is_json = "json" in cols.get("open_ports", {}).get("type", "")
        saved = 0
        for ip in sorted(hosts):
            ports = sorted(hosts[ip])

            if ports_scanned:
                ports_value = (json.dumps(ports) if is_json
                               else (",".join(str(p) for p in ports) if ports else "none"))
                device_type = guess_device_type(ports)
            else:
                ports_value = "[]" if is_json else "not scanned"
                device_type = "Unknown (host discovery only)"

            new_fields = {}
            if "device_type" in cols:
                new_fields["device_type"] = device_type
            if "open_ports" in cols:
                new_fields["open_ports"] = ports_value
            if "scan_time" in cols:
                new_fields["scan_time"] = now
            if scan_id is not None:
                new_fields["scan_id"] = scan_id

            if ports_scanned:
                update_fields = dict(new_fields)
            else:
                update_fields = {k: new_fields[k] for k in ("scan_time", "scan_id")
                                 if k in new_fields}

            cur.execute("SELECT 1 FROM discovered_devices WHERE ip_address = %s LIMIT 1", (ip,))
            exists = cur.fetchall()

            if exists:
                if update_fields:
                    assignments = ", ".join(f"`{k}` = %s" for k in update_fields)
                    cur.execute(
                        f"UPDATE discovered_devices SET {assignments} WHERE ip_address = %s",
                        list(update_fields.values()) + [ip],
                    )
            else:
                names = ["ip_address"] + list(new_fields)
                placeholders = ", ".join(["%s"] * len(names))
                cur.execute(
                    f"INSERT INTO discovered_devices ({', '.join('`' + n + '`' for n in names)}) "
                    f"VALUES ({placeholders})",
                    [ip] + list(new_fields.values()),
                )
            saved += 1

        conn.commit()
        cur.close()
        return saved
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Running the scanner script
# --------------------------------------------------------------------------

def _finish(status, message, output=""):
    global scan_proc
    with scan_lock:
        scan_state.update(status=status, message=message, output=output,
                          finished=time.time())
        scan_proc = None


def scan_worker(cmd, port_scan):
    """Runs the scanner script in a background thread so the request returns at once."""
    global scan_proc
    flags = {"timed_out": False}

    try:
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=SCANNER_DIR,
        )
    except Exception as e:
        _finish("error", f"Could not start the scanner: {e}")
        return

    with scan_lock:
        scan_proc = proc
        stop_now = scan_state["stop_requested"]
    if stop_now:
        proc.terminate()

    def kill_if_too_long():
        flags["timed_out"] = True
        proc.kill()

    timer = threading.Timer(SCAN_MAX_SECONDS, kill_if_too_long)
    timer.daemon = True
    timer.start()

    lines = []
    size = 0
    try:
        # Python turns the scanner's "\r" progress updates into separate lines here.
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if PROGRESS_RE.match(line):
                with scan_lock:
                    scan_state["progress"] = line.strip()
                continue
            if size < 200_000:
                lines.append(line)
                size += len(line)
        proc.wait()
    finally:
        timer.cancel()

    output = "\n".join(lines).strip()

    with scan_lock:
        stopped = scan_state["stop_requested"]

    if stopped:
        _finish("stopped", "Scan stopped.", output)
        return
    if flags["timed_out"]:
        _finish("error", f"Scan ran longer than {SCAN_MAX_SECONDS // 60} minutes and was stopped.", output)
        return
    if proc.returncode != 0:
        _finish("error", extract_error(output), "")
        return

    hosts = parse_scanner_output(output, port_scan)
    if not hosts:
        msg = ("Scan complete: no open ports found on any host. Nothing saved."
               if port_scan else "Scan complete: no live hosts detected. Nothing saved.")
        _finish("done", msg, output)
        return

    try:
        saved = save_results(hosts, ports_scanned=port_scan)
    except Exception as e:
        _finish("error", f"Scan finished but saving to the database failed: {e}", output)
        return

    kind = "host(s) with open ports" if port_scan else "live host(s)"
    _finish("done", f"Scan complete: {saved} {kind} saved to database.", output)


def flag_name(token):
    if token.startswith("--"):
        return token.split("=", 1)[0]
    return token[:2]


def is_ports_flag(token):
    return (token == "--ports" or token.startswith("--ports=")
            or (token.startswith("-p") and not token.startswith("--")))


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT cpu_usage, ram_usage, latency FROM system_metrics "
            "ORDER BY scan_time DESC, id DESC LIMIT 1"
        )
        latest_metric = cursor.fetchone()
        cursor.close()
        conn.close()
        if not latest_metric:
            return jsonify({"cpu_usage": 0, "ram_usage": 0, "latency": 0})
        return jsonify(latest_metric)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/devices', methods=['GET'])
def get_devices():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT ip_address, device_type, open_ports FROM discovered_devices")
        devices = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def prepare_scan(data):
    """
    Validate the request body and build the scanner arguments.
    Returns (args, port_scan, scanner, error_response). On failure, only
    error_response is set (a ready-to-return Flask response).
    """
    scanner = find_scanner()
    if not scanner:
        return None, None, None, (jsonify({"error": "Scanner script not found. Put netscan.py "
                                                    "in the same folder as app.py."}), 500)

    args = data.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None, None, None, (jsonify({"error": "Invalid scan arguments."}), 400)
    args = [a.strip() for a in args if a.strip()]
    if len(args) > 20 or any(len(a) > 200 for a in args):
        return None, None, None, (jsonify({"error": "Too many or too long scan arguments."}), 400)

    for a in args:
        if not a.startswith("-"):
            continue
        name = flag_name(a)
        if name == "--allow-public" and not ALLOW_PUBLIC_SCANS:
            return None, None, None, (jsonify({"error": "--allow-public is disabled in the dashboard. "
                                                        "Only private/local networks can be scanned here."}), 403)
        if name not in ALLOWED_SCAN_FLAGS:
            return None, None, None, (jsonify({"error": f"Option '{a}' isn't available from the dashboard. "
                                                        "Allowed: -p, -t, --timeout, --max-hosts, "
                                                        "--no-skip-unreachable."}), 400)

    if not args or args[0].startswith("-"):
        target = local_default_target()
        if not target:
            return None, None, None, (jsonify({"error": "Couldn't detect your local network. "
                                                        "Give a target, e.g. scan 192.168.1.0/24"}), 400)
        args = [target] + args

    port_scan = any(is_ports_flag(a) for a in args)
    return args, port_scan, scanner, None


def extract_scan_details(output):
    """
    Pull the 'Target hosts / Mode / Threads / ...' block out of the scanner's
    output. The scanner prints it just before asking 'Proceed with this scan?'.
    """
    lines = output.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("Target hosts")), None)
    if start is None:
        return None
    details = []
    for line in lines[start:]:
        if line.startswith("Proceed with this scan?"):
            break
        details.append(line.rstrip())
    return "\n".join(details).strip() or None


@app.route('/api/scan/preview', methods=['POST'])
def preview_scan():
    """
    Body: {"args": [...]}  (same as /api/scan)
    Runs the scanner WITHOUT -y and with no input available, so it prints its
    scan details (targets, mode, threads, timeout, total checks) and then stops
    at its own confirmation prompt. Nothing is scanned.
    """
    data = request.get_json(silent=True) or {}
    args, port_scan, scanner, err = prepare_scan(data)
    if err:
        return err

    try:
        proc = subprocess.run(
            [sys.executable, "-u", scanner] + args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(os.environ, PYTHONIOENCODING="utf-8"),
            cwd=SCANNER_DIR,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timed out working out the scan details."}), 500
    except Exception as e:
        return jsonify({"error": f"Could not start the scanner: {e}"}), 500

    details = extract_scan_details(proc.stdout)
    if details is None:
        # Scanner stopped before the confirmation step: [ERROR] / [BLOCKED] / bad args
        return jsonify({"error": extract_error(proc.stdout)}), 400

    return jsonify({"details": details, "args": args, "port_scan": port_scan})


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """
    Body: {"args": ["192.168.1.0/24", "-p", "22,80"]}
    The args are handed to the scanner script exactly as if typed after
    "python netscan.py". With no target, the local /24 network is used.
    """
    data = request.get_json(silent=True) or {}
    args, port_scan, scanner, err = prepare_scan(data)
    if err:
        return err

    cmd = [sys.executable, "-u", scanner] + args + ["-y"]
    shown = "netscan.py " + " ".join(args)

    with scan_lock:
        if scan_state["status"] == "running":
            return jsonify({"error": "A scan is already running."}), 409
        scan_state.update(
            status="running",
            message="Scan in progress.",
            command=shown,
            started=time.time(),
            finished=None,
            progress="",
            output="",
            stop_requested=False,
        )

    threading.Thread(target=scan_worker, args=(cmd, port_scan), daemon=True).start()
    mode = "port scan" if port_scan else "host discovery only"
    return jsonify({"message": f"Running {shown}  ({mode})..."}), 202


@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    with scan_lock:
        if scan_state["status"] != "running":
            return jsonify({"error": "No scan is running."}), 409
        scan_state["stop_requested"] = True
        proc = scan_proc
    if proc is not None:
        proc.terminate()
    return jsonify({"message": "Stopping scan..."})


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    with scan_lock:
        state = dict(scan_state)
    state.pop("stop_requested", None)
    end = state["finished"] or time.time()
    state["elapsed"] = int(end - state["started"]) if state["started"] else 0
    if state["status"] == "running":
        state["output"] = ""
    return jsonify(state)


@app.route('/api/exec', methods=['POST'])
def run_command():
    data = request.get_json(silent=True) or {}
    parts = data.get("command", "").strip().split()
    if not parts or parts[0].lower() not in ALLOWED:
        name = parts[0] if parts else ""
        return jsonify({"output": f"'{name}' is not an allowed command."}), 403
    try:
        result = subprocess.run(parts, capture_output=True, text=True, timeout=20)
        return jsonify({"output": result.stdout + result.stderr})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "Command timed out."})
    except Exception as e:
        return jsonify({"output": str(e)}), 500


if __name__ == '__main__':
    # Flask's debug reloader runs this file twice; only the reloaded copy
    # (WERKZEUG_RUN_MAIN == "true") starts the background simulation.
    if SIMULATE_LIVE_METRICS and os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Thread(target=simulated_metrics_loop, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=True)
