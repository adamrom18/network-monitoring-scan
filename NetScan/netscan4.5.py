#!/usr/bin/env python3
"""
netscan.py - A threaded TCP host/port scanner. Requires administrator/root.

WHAT THIS TOOL DOES
    Given an IP range (CIDR or start-end):
      * Without -p : performs host discovery only and lists hosts that are up.
      * With -p    : scans TCP ports and displays open ports per host.
                     "-p" alone scans the 1000 most common ports.
                     "-p 22,80,443" or "-p 1-65535" scans exactly what you ask for.

LEGAL / ETHICAL WARNING
    Only run this against systems and networks you own, or for which you
    have explicit, documented authorization to test. Scanning networks
    without permission may violate laws such as the U.S. Computer Fraud
    and Abuse Act, the UK Computer Misuse Act, or similar legislation in
    your country, even if no damage is done.

USAGE (run from an elevated/administrator prompt, or with sudo)
    python netscan.py 192.168.1.0/24                 # host discovery only
    python netscan.py 192.168.1.0/24 -p              # top 1000 common ports
    python netscan.py 10.0.0.1-10.0.0.50 -p 1-65535 -t 500
    python netscan.py 203.0.113.10 -p 80,443 --allow-public --yes

    Run "python netscan.py -h" for full option list.
"""

import argparse
import ctypes
import errno
import ipaddress
import os
import queue
import socket
import sys
import threading
import time
from datetime import datetime


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

MAX_THREADS = 1000        # hard cap on worker threads
DEFAULT_MAX_HOSTS = 1024  # refuse ranges larger than this unless overridden

# Ports probed during host discovery (when -p is not given).
DISCOVERY_PORTS = [80, 443, 22, 21, 23, 25, 53, 135, 139, 445, 3389, 8080]

# Connection-refused codes: a refusal means the host is alive (it answered).
REFUSED_CODES = {errno.ECONNREFUSED, 10061}  # 10061 = WSAECONNREFUSED (Windows)

# Commonly used ports above 1024. The top-1000 list is built from these plus
# the lowest-numbered ports (1, 2, 3, ...) until 1000 ports are reached.
# This is an APPROXIMATION of nmap's "top 1000"; see build_top_ports().
COMMON_HIGH_PORTS = [
    1025, 1026, 1027, 1028, 1029, 1030, 1099, 1433, 1434, 1521, 1720, 1723,
    1755, 1900, 2000, 2001, 2049, 2121, 2181, 2222, 2375, 2376, 2483, 2484,
    3000, 3128, 3306, 3389, 3690, 4000, 4443, 4444, 4567, 4848, 5000, 5001,
    5060, 5061, 5432, 5555, 5601, 5631, 5666, 5800, 5900, 5901, 5985, 5986,
    6000, 6379, 6443, 6667, 7001, 7002, 7070, 7443, 7777, 8000, 8001, 8008,
    8009, 8080, 8081, 8082, 8083, 8085, 8086, 8088, 8090, 8443, 8444, 8500,
    8600, 8888, 8983, 9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418,
    9443, 9999, 10000, 10250, 11211, 15672, 27017, 27018, 32768, 49152,
    49153, 49154, 49155, 49156, 49157, 50000, 50070,
]


def build_top_ports(count=1000):
    ports = set(COMMON_HIGH_PORTS)
    p = 1
    while len(ports) < count and p <= 65535:
        ports.add(p)
        p += 1
    return sorted(ports)


TOP_PORTS = build_top_ports(1000)


# --------------------------------------------------------------------------
# Privilege check
# --------------------------------------------------------------------------

def is_admin():
    """Return True if running as Administrator (Windows) or root (Unix)."""
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def is_private_or_reserved(ip_obj):
    """Return True if the address is private, loopback, link-local, or reserved."""
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    )


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def parse_targets(target_str):
    """
    Parse a target specification into a list of ipaddress objects.
    Accepts:
        - single IP:        192.168.1.10
        - CIDR notation:    192.168.1.0/24
        - dash range:       192.168.1.1-192.168.1.50  (or 192.168.1.1-50)
    """
    target_str = target_str.strip()

    if "/" in target_str:
        network = ipaddress.ip_network(target_str, strict=False)
        return list(network.hosts()) if network.num_addresses > 2 else list(network)

    if "-" in target_str:
        start_str, end_str = target_str.split("-", 1)
        start_ip = ipaddress.ip_address(start_str.strip())
        if "." not in end_str:
            parts = start_str.strip().split(".")
            parts[-1] = end_str.strip()
            end_ip = ipaddress.ip_address(".".join(parts))
        else:
            end_ip = ipaddress.ip_address(end_str.strip())

        if int(end_ip) < int(start_ip):
            raise ValueError("Range end must not be before range start.")

        return [ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1)]

    return [ipaddress.ip_address(target_str)]


def parse_ports(port_str):
    """Parse a port spec like '80,443,1000-1010' into a sorted list of ints."""
    ports = set()
    for chunk in port_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"Invalid port range: {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(chunk)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


# --------------------------------------------------------------------------
# Scanning logic
# --------------------------------------------------------------------------

def probe(ip, port, timeout):
    """
    Attempt a TCP connect. Returns "open", "closed" (refused, host is up),
    or "filtered" (no answer / error).
    """
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
    except OSError:
        return "filtered"
    if result == 0:
        return "open"
    if result in REFUSED_CODES:
        return "closed"
    return "filtered"


def worker(work_queue, open_ports, up_hosts, lock, timeout, progress, total):
    while True:
        try:
            ip, port = work_queue.get_nowait()
        except queue.Empty:
            return

        status = probe(ip, port, timeout)

        with lock:
            if status in ("open", "closed"):
                up_hosts.add(str(ip))
            if status == "open":
                open_ports.setdefault(str(ip), []).append(port)
            progress[0] += 1
            done = progress[0]
            if done % 200 == 0 or done == total:
                sys.stdout.write(f"\r  scanned {done}/{total} checks...")
                sys.stdout.flush()


def run_scan(targets, ports, thread_count, timeout):
    work_queue = queue.Queue()
    for ip in targets:
        for port in ports:
            work_queue.put((ip, port))

    total = work_queue.qsize()
    open_ports = {}
    up_hosts = set()
    lock = threading.Lock()
    progress = [0]

    thread_count = min(thread_count, MAX_THREADS, max(1, total))
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(
            target=worker,
            args=(work_queue, open_ports, up_hosts, lock, timeout, progress, total),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print()
    return open_ports, up_hosts


# --------------------------------------------------------------------------
# Safety / confirmation
# --------------------------------------------------------------------------

def print_warning_banner():
    print("=" * 72)
    print(" NETWORK SCANNER - AUTHORIZED USE ONLY")
    print("=" * 72)
    print(
        " Scanning devices or networks without explicit permission from the\n"
        " owner may be illegal in your jurisdiction, even if no harm is done.\n"
        " By continuing, you confirm that you own this network/these hosts,\n"
        " or have documented authorization (e.g. a pentest engagement letter)\n"
        " to scan them."
    )
    print("=" * 72)


def interactive_confirmation(targets, ports, threads, args, port_scan):
    print(f"\nTarget hosts : {len(targets)}")
    shown = targets if len(targets) <= 10 else targets[:5]
    for ip in shown:
        print(f"    - {ip}")
    if len(targets) > 10:
        print(f"    ... and {len(targets) - 5} more")

    if port_scan:
        preview = f"{ports[:10]}{'...' if len(ports) > 10 else ''}"
        print(f"Mode         : port scan ({len(ports)} port(s) -> {preview})")
    else:
        print(f"Mode         : host discovery only (probing {len(ports)} ports per host)")
    print(f"Threads      : {threads}")
    print(f"Timeout      : {args.timeout}s per connection")
    print(f"Total checks : {len(targets) * len(ports)}")

    if args.yes:
        return True

    answer = input("\nProceed with this scan? Type 'yes' to continue: ").strip().lower()
    return answer == "yes"


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def sort_ips(ips):
    return sorted(ips, key=lambda x: ipaddress.ip_address(x))


def main():
    parser = argparse.ArgumentParser(
        description="Threaded TCP network scanner (requires admin/root).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        help="Target IP, CIDR range, or dash range, e.g. 192.168.1.0/24, "
             "192.168.1.1-192.168.1.50, or 192.168.1.1-50",
    )
    parser.add_argument(
        "-p", "--ports",
        nargs="?",
        const="top1000",
        default=None,
        help="Scan ports and display results. With no value, scans the 1000 most "
             "common ports. Otherwise e.g. '22,80,443' or '1-65535' (no port limit). "
             "If omitted, only host discovery is performed.",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help=f"Number of worker threads, max {MAX_THREADS} (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Per-connection timeout in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=DEFAULT_MAX_HOSTS,
        help=f"Safety limit on number of hosts in range (default: {DEFAULT_MAX_HOSTS})",
    )
    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="Explicitly allow scanning public (non-private) IP addresses. "
             "Only use this if you are certain you are authorized to do so.",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip the interactive 'proceed?' confirmation prompt.",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional file path to write results to (plain text).",
    )

    args = parser.parse_args()

    if not is_admin():
        print(
            "[ERROR] This tool must be run with administrator privileges.\n"
            "        Windows: open Command Prompt / PowerShell as Administrator.\n"
            "        Linux/macOS: run with sudo."
        )
        sys.exit(1)

    print_warning_banner()

    if args.threads < 1:
        print("\n[ERROR] Thread count must be at least 1.")
        sys.exit(1)
    threads = args.threads
    if threads > MAX_THREADS:
        print(f"\n[NOTE] Thread count capped at {MAX_THREADS} (requested {threads}).")
        threads = MAX_THREADS

    port_scan = args.ports is not None

    try:
        targets = parse_targets(args.target)
        if not port_scan:
            ports = DISCOVERY_PORTS
        elif args.ports == "top1000":
            ports = TOP_PORTS
        else:
            ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    if not targets:
        print("\n[ERROR] No valid targets parsed from input.")
        sys.exit(1)
    if not ports:
        print("\n[ERROR] No valid ports parsed from input.")
        sys.exit(1)

    non_private = [ip for ip in targets if not is_private_or_reserved(ip)]
    if non_private and not args.allow_public:
        sample = ", ".join(str(ip) for ip in non_private[:5])
        more = f" (+{len(non_private) - 5} more)" if len(non_private) > 5 else ""
        print("\n[BLOCKED] The target range includes public (non-private) IP addresses:")
        print(f"    {sample}{more}")
        print(
            "Public IP scanning is off by default to reduce the chance of scanning\n"
            "a network you don't own. If you are certain you have authorization,\n"
            "re-run with --allow-public."
        )
        sys.exit(1)

    if len(targets) > args.max_hosts:
        print(
            f"\n[BLOCKED] Target range contains {len(targets)} hosts, which exceeds "
            f"the limit of {args.max_hosts}.\n"
            "Narrow your range, or raise the limit with --max-hosts N."
        )
        sys.exit(1)

    if not interactive_confirmation(targets, ports, threads, args, port_scan):
        print("Aborted.")
        sys.exit(0)

    print(f"\nStarting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    start = time.time()

    open_ports, up_hosts = run_scan(targets, ports, threads, args.timeout)

    elapsed = time.time() - start
    print(f"Scan completed in {elapsed:.2f} seconds.\n")

    lines = []
    if port_scan:
        if not open_ports:
            lines.append("No open ports found on any scanned host.")
        else:
            lines.append("Open ports:")
            for ip in sort_ips(open_ports):
                lines.append(f"  {ip}: {', '.join(str(p) for p in sorted(open_ports[ip]))}")
    else:
        if not up_hosts:
            lines.append("No live hosts detected.")
        else:
            lines.append(f"Hosts up ({len(up_hosts)}):")
            for ip in sort_ips(up_hosts):
                lines.append(f"  {ip}")
        lines.append("\n(Use -p to scan ports on these hosts.)")

    print("\n".join(lines))

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(f"Scan of {args.target} (ports: {args.ports or 'host discovery'})\n")
                f.write(f"Run at: {datetime.now().isoformat()}\n\n")
                f.write("\n".join(lines) + "\n")
            print(f"\nResults written to {args.output}")
        except OSError as e:
            print(f"\n[ERROR] Could not write output file: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Exiting.")
        sys.exit(1)
