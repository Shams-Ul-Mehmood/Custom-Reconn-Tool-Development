
"""
Active Recon Module: Port Scanning

Usage:
    python3 portscan.py <target> [-p PORTS] [-t THREADS] [--nmap] [-o out.json]

Examples:
    python3 portscan.py 192.168.1.10
    python3 portscan.py scanme.nmap.org -p 1-1024 -t 200
    python3 portscan.py 10.0.0.5 -p 22,80,443,8080 --nmap
"""
import argparse
import concurrent.futures
import ipaddress
import json
import logging
import socket
import sys
import time
from dataclasses import dataclass, asdict, field
from typing import List, Optional



def parse_arguments():
    parser = argparse.ArgumentParser(description="Custom Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")

    # --ports now accepts an optional port-spec value instead of being a plain flag.
    #   --ports                -> "1-1024" (default range)
    #   --ports 22,80,443      -> that exact spec
    #   (flag omitted)         -> None (skip port scan)
    parser.add_argument(
        "--ports", nargs="?", const="1-1024", default=None,
        help="Scan open ports. Optionally pass a spec, e.g. '22,80,1000-1010' "
             "(default range '1-1024' if flag given with no value)"
    )

    parser.add_argument("--techdetect", action="store_true", help="Detect web technologies")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level")

    # Port-scan specific options (used by run_portscan)
    parser.add_argument("--nmap", action="store_true", help="Use nmap backend instead of raw sockets")
    parser.add_argument("--nmap-args", dest="nmap_args", default="-sV --version-light",
                         help="Arguments passed to nmap when --nmap is used")
    parser.add_argument("--timeout", type=float, default=0.75, help="Per-port socket timeout (seconds)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Max concurrent socket workers")
    parser.add_argument("--banners", action="store_true", help="Attempt banner grabbing on open ports")

    return parser.parse_args()

# -----------
# Data model
# -----------

@dataclass
class PortResult:
    port: int
    state: str                  # "open", "closed", "filtered"
    service: Optional[str] = None
    banner: Optional[str] = None
    latency_ms: Optional[float] = None


@dataclass
class ScanResult:
    target: str
    resolved_ip: str
    started_at: float
    finished_at: float = 0.0
    open_ports: List[PortResult] = field(default_factory=list)
    scanned_port_count: int = 0
    backend: str = "socket"

    def to_dict(self):
        d = asdict(self)
        d["duration_sec"] = round(self.finished_at - self.started_at, 3)
        return d


# --------
# Helpers
# --------

def resolve_target(target: str) -> str:
    # Resolve hostname to an IP address (raises socket.gaierror on failure).
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def parse_port_spec(spec: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of unique ints.
    Supports comma-separated values and ranges, e.g. "22,80,1000-1010".
    """
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


COMMON_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}


def guess_service(port: int) -> Optional[str]:
    # Best-effort service name lookup: our table first, then socket's DB.
    if port in COMMON_SERVICE_NAMES:
        return COMMON_SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


# -------------------------------------------------
# Socket-based scanner (no external dependencies)
# -------------------------------------------------

class SocketScanner:
    
    def __init__(self, timeout: float = 0.75, max_workers: int = 100,
                 grab_banner: bool = False):
        self.timeout = timeout
        self.max_workers = max_workers
        self.grab_banner = grab_banner

    def _check_port(self, ip: str, port: int) -> PortResult:
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                latency = (time.perf_counter() - start) * 1000

                if result != 0:
                    return PortResult(port=port, state="closed", latency_ms=round(latency, 2))

                banner = None
                if self.grab_banner:
                    # Import locally to avoid a circular import at module load time.
                    from modules.banner import grab_banner
                    banner = grab_banner(ip, port, sock=sock, timeout=self.timeout)

                return PortResult(
                    port=port,
                    state="open",
                    service=guess_service(port),
                    banner=banner,
                    latency_ms=round(latency, 2),
                )
        except socket.timeout:
            return PortResult(port=port, state="filtered")
        except OSError:
            return PortResult(port=port, state="closed")

    def scan(self, target: str, ports: List[int]) -> ScanResult:
        ip = resolve_target(target)
        result = ScanResult(target=target, resolved_ip=ip, started_at=time.time(),
                             scanned_port_count=len(ports), backend="socket")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._check_port, ip, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                port_result = fut.result()
                if port_result.state == "open":
                    result.open_ports.append(port_result)

        result.open_ports.sort(key=lambda r: r.port)
        result.finished_at = time.time()
        return result


# -----------------------------------------------------------------
# python-nmap wrapper (requires the `nmap` binary to be installed)
# -----------------------------------------------------------------

class NmapScanner:

    def __init__(self, arguments: str = "-sV --version-light"):
        try:
            import nmap  # python-nmap
        except ImportError as e:
            raise RuntimeError(
                "python-nmap is not installed. Install it with:\n"
                "  pip install python-nmap"
            ) from e
        self._nmap_module = nmap
        try:
            self.scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            raise RuntimeError(
                "The 'nmap' binary was not found on this system. Install it via "
                "your OS package manager (e.g., 'apt install nmap') or use "
                "SocketScanner instead."
            ) from e
        self.arguments = arguments

    def scan(self, target: str, ports: List[int]) -> ScanResult:
        ip = resolve_target(target)
        port_str = ",".join(str(p) for p in ports)
        started = time.time()

        self.scanner.scan(hosts=ip, ports=port_str, arguments=self.arguments)

        result = ScanResult(target=target, resolved_ip=ip, started_at=started,
                             scanned_port_count=len(ports), backend="nmap")

        if ip in self.scanner.all_hosts():
            tcp_data = self.scanner[ip].get("tcp", {})
            for port, info in sorted(tcp_data.items()):
                if info.get("state") == "open":
                    service = info.get("name") or None
                    version = " ".join(
                        filter(None, [info.get("product"), info.get("version")])
                    ) or None
                    result.open_ports.append(PortResult(
                        port=port,
                        state="open",
                        service=service,
                        banner=version,
                    ))

        result.finished_at = time.time()
        return result


def run_portscan(target: str, ports: str = None, use_nmap: bool = False,
                  nmap_args: str = "-sV --version-light", timeout: float = 0.75,
                  threads: int = 100, banners: bool = False) -> dict:
    """
    Run a port scan against `target` and return a result dict:

        {
            "target": str,
            "success": bool,
            "data": {...ScanResult.to_dict()...},   # present on success
            "error": str,                            # present on failure
        }

    `ports` is a port-spec string, e.g. "22,80,443" or "1-1024".
    If omitted/None, defaults to the well-known range 1-1024.
    """
    try:
        port_list = parse_port_spec(ports) if ports else list(range(1, 1025))
    except ValueError as e:
        return {"target": target, "success": False, "error": f"Invalid port specification: {e}"}

    if not port_list:
        return {"target": target, "success": False, "error": "No valid ports to scan."}

    try:
        if use_nmap:
            scanner = NmapScanner(arguments=nmap_args)
        else:
            scanner = SocketScanner(timeout=timeout, max_workers=threads, grab_banner=banners)
        result = scanner.scan(target, port_list)
    except (socket.gaierror, RuntimeError) as e:
        return {"target": target, "success": False, "error": str(e)}

    return {"target": target, "success": True, "data": result.to_dict()}


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Change this to test any domain you want
    target = "example.com"

    print()
    print("=" * 55)
    print(f"  PORTS SCANNING")
    print(f"  Target: {target}")
    print("=" * 55)

    result = run_portscan(target, ports="1-1024")
    print(json.dumps(result, indent=2))

