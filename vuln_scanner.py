#!/usr/bin/env python3
"""
Mini Vulnerability Scanner
==========================

A small educational tool for learning the basics of penetration testing
and vulnerability assessment. It performs three things:

  1. Port scanning       - which common TCP ports are open
  2. Banner/version grab - what service/software is running, and whether
                            it looks out of date against a small reference list
  3. Basic config checks - a handful of well-known weak-configuration signs
                            (missing HTTP security headers, anonymous FTP,
                            plaintext protocols, self-signed/expired TLS certs)

It then writes a plain-text and Markdown report summarizing findings by
severity.

IMPORTANT - AUTHORIZED USE ONLY
--------------------------------
Only run this against systems you own, or systems you have explicit written
permission to test (e.g. your own homelab, a machine you control, or a
target inside a scoped penetration-testing engagement). Scanning systems
without authorization is illegal in most jurisdictions (in the US, this can
fall under the Computer Fraud and Abuse Act) and can trigger abuse alerts
even when no harm is intended. This script does not exploit anything - it
only connects, reads banners, and reports what it finds.

Usage
-----
    python3 vuln_scanner.py TARGET [options]

Examples
    python3 vuln_scanner.py 127.0.0.1
    python3 vuln_scanner.py scanme.example.com --ports 21,22,80,443,3306
    python3 vuln_scanner.py 192.168.1.10 --ports common --output report

Run `python3 vuln_scanner.py --help` for all options.
"""

import argparse
import concurrent.futures
import datetime
import socket
import ssl
import sys
import re
from dataclasses import dataclass, field

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


# ---------------------------------------------------------------------------
# Reference data (small and illustrative, NOT a substitute for a real CVE feed)
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Plaintext / historically risky protocols worth flagging just for being open
INHERENTLY_RISKY_PORTS = {
    21: "FTP transmits credentials and data in plaintext; prefer SFTP/FTPS.",
    23: "Telnet transmits everything, including passwords, in plaintext.",
    111: "RPCbind has a history of information-disclosure and DoS issues.",
    139: "NetBIOS/SMBv1 exposure has a long history of critical CVEs.",
    445: "SMB has been the vector for major worms (e.g. WannaCry); should not face the internet.",
    3389: "RDP exposed to the internet is a top brute-force/ransomware target.",
    5900: "VNC is often run with weak or no authentication.",
    6379: "Redis has no auth by default in many setups and is a common ransomware target.",
    27017: "MongoDB has shipped with no-auth-by-default in older versions; frequently scanned for by botnets.",
}

# Very small illustrative "minimum reasonably current version" table.
# Real assessments should check a live CVE database (e.g. NVD) instead.
MIN_SAFE_VERSIONS = {
    "openssh": (8, 0),
    "apache": (2, 4, 50),
    "nginx": (1, 22, 0),
    "vsftpd": (3, 0, 3),
    "proftpd": (1, 3, 8),
    "mysql": (8, 0, 0),
    "postgresql": (13, 0),
    "openssl": (1, 1, 1),
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
]


@dataclass
class Finding:
    severity: str   # "info" | "low" | "medium" | "high"
    title: str
    detail: str


@dataclass
class ScanResult:
    target: str
    open_ports: dict = field(default_factory=dict)   # port -> banner
    findings: list = field(default_factory=list)


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


# ---------------------------------------------------------------------------
# Port scanning + banner grabbing
# ---------------------------------------------------------------------------

def scan_port(host, port, timeout=1.0):
    """Try to connect to a port and grab whatever banner it offers."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return None
            banner = grab_banner(s, host, port, timeout)
            return banner
    except (socket.timeout, OSError):
        return None


def grab_banner(sock, host, port, timeout):
    """Best-effort banner grab. Some services talk first; HTTP needs a nudge."""
    sock.settimeout(timeout)
    try:
        if port in (80, 8080):
            sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = sock.recv(2048)
            return data.decode(errors="ignore").strip()
        if port in (443, 8443):
            return grab_tls_banner(host, port, timeout)
        # Most other services (SSH, FTP, SMTP, POP3, IMAP...) send a greeting
        # as soon as the connection opens.
        data = sock.recv(256)
        return data.decode(errors="ignore").strip()
    except (socket.timeout, OSError, UnicodeDecodeError):
        return ""


def grab_tls_banner(host, port, timeout):
    """Wrap in TLS, fetch the cert, and issue a minimal HTTP HEAD."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect the cert ourselves, not fail on it
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False)
                tls_sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                data = tls_sock.recv(2048).decode(errors="ignore").strip()
                return data
    except Exception:
        return ""


def run_port_scan(host, ports, timeout, max_workers=100):
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            banner = fut.result()
            if banner is not None:
                open_ports[port] = banner
    return open_ports


# ---------------------------------------------------------------------------
# Version parsing / outdated-software detection
# ---------------------------------------------------------------------------

def parse_version(text):
    """Pull a (software_name, version_tuple) guess out of a banner string."""
    text_l = text.lower()
    patterns = {
        "openssh": r"openssh[_/]?(\d+)\.(\d+)(?:p(\d+))?",
        "apache": r"apache/(\d+)\.(\d+)\.?(\d+)?",
        "nginx": r"nginx/(\d+)\.(\d+)\.?(\d+)?",
        "vsftpd": r"vsftpd\s*(\d+)\.(\d+)\.?(\d+)?",
        "proftpd": r"proftpd\s*(\d+)\.(\d+)\.?(\d+)?",
        "mysql": r"mysql[^\d]*(\d+)\.(\d+)\.?(\d+)?",
        "postgresql": r"postgresql\s*(\d+)\.?(\d+)?",
        "openssl": r"openssl/(\d+)\.(\d+)\.(\d+)",
    }
    for name, pattern in patterns.items():
        m = re.search(pattern, text_l)
        if m:
            parts = tuple(int(g) for g in m.groups() if g is not None)
            return name, parts
    return None, None


def check_outdated(name, version):
    minimum = MIN_SAFE_VERSIONS.get(name)
    if not minimum or not version:
        return None
    length = max(len(version), len(minimum))
    v = version + (0,) * (length - len(version))
    m = minimum + (0,) * (length - len(minimum))
    if v < m:
        return f"{name} {'.'.join(map(str, version))} is older than the reference baseline {'.'.join(map(str, minimum))}"
    return None


# ---------------------------------------------------------------------------
# HTTP header / config checks
# ---------------------------------------------------------------------------

def check_http_headers(host, port, use_tls):
    if not HAVE_REQUESTS:
        return []
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    findings = []
    try:
        resp = requests.head(url, timeout=3, verify=False, allow_redirects=True)
        headers = resp.headers
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if missing:
            findings.append(Finding(
                "low",
                f"Missing HTTP security headers on {url}",
                "Missing: " + ", ".join(missing) +
                ". These headers help mitigate clickjacking, MIME-sniffing, and downgrade attacks."
            ))
        server_hdr = headers.get("Server")
        if server_hdr:
            name, version = parse_version(server_hdr)
            if name and version:
                msg = check_outdated(name, version)
                if msg:
                    findings.append(Finding("medium", f"Outdated web server on {url}", msg))
    except Exception:
        pass
    return findings


def check_tls_cert(host, port):
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False)
                proto = tls_sock.version()
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(Finding(
                        "high",
                        f"Weak TLS protocol on port {port}",
                        f"Server negotiated {proto}, which is deprecated and considered insecure."
                    ))
                if cert:
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                            if days_left < 0:
                                findings.append(Finding("high", f"Expired TLS certificate on port {port}",
                                                          f"Certificate expired {abs(days_left)} days ago."))
                            elif days_left < 30:
                                findings.append(Finding("medium", f"TLS certificate expiring soon on port {port}",
                                                          f"Certificate expires in {days_left} days."))
                        except ValueError:
                            pass
                else:
                    findings.append(Finding("info", f"No certificate details retrieved on port {port}",
                                              "Could not inspect certificate metadata."))
    except ssl.SSLError as e:
        findings.append(Finding("info", f"TLS handshake issue on port {port}", str(e)))
    except Exception:
        pass
    return findings


def check_ftp_anonymous(host, port, timeout=3):
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.recv(256)
            s.sendall(b"USER anonymous\r\n")
            resp1 = s.recv(256).decode(errors="ignore")
            s.sendall(b"PASS anonymous@example.com\r\n")
            resp2 = s.recv(256).decode(errors="ignore")
            if "230" in resp2:  # 230 = login successful
                findings.append(Finding(
                    "high",
                    f"Anonymous FTP login allowed on port {port}",
                    "The FTP server accepted an anonymous login. Anonymous FTP should be disabled "
                    "unless deliberately used for public file distribution."
                ))
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_findings(host, open_ports):
    findings = []

    for port, banner in sorted(open_ports.items()):
        service = COMMON_PORTS.get(port, "unknown")
        findings.append(Finding("info", f"Open port {port} ({service})",
                                 f"Banner: {banner[:120] or '(no banner)'}"))

        if port in INHERENTLY_RISKY_PORTS:
            findings.append(Finding("medium", f"Inherently risky service exposed on port {port}",
                                     INHERENTLY_RISKY_PORTS[port]))

        name, version = parse_version(banner)
        if name and version:
            msg = check_outdated(name, version)
            if msg:
                findings.append(Finding("medium", f"Possibly outdated software on port {port}", msg))

        if port == 21:
            findings.extend(check_ftp_anonymous(host, port))
        if port in (80, 8080):
            findings.extend(check_http_headers(host, port, use_tls=False))
        if port in (443, 8443):
            findings.extend(check_http_headers(host, port, use_tls=True))
            findings.extend(check_tls_cert(host, port))

    return findings


def print_report(result):
    print(f"\n=== Vulnerability scan report for {result.target} ===")
    print(f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}Z\n")

    if not result.open_ports:
        print("No open ports found in the scanned range.\n")
    else:
        print(f"Open ports ({len(result.open_ports)}):")
        for port in sorted(result.open_ports):
            print(f"  {port:>6}  {COMMON_PORTS.get(port, 'unknown')}")
        print()

    findings_sorted = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    print(f"Findings ({len(findings_sorted)}):")
    for f in findings_sorted:
        print(f"  [{f.severity.upper():6}] {f.title}")
        print(f"           {f.detail}")
    print()


def write_reports(result, base_path):
    txt_path = f"{base_path}.txt"
    md_path = f"{base_path}.md"
    findings_sorted = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_sorted:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    with open(txt_path, "w") as fh:
        fh.write(f"Vulnerability scan report for {result.target}\n")
        fh.write(f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}Z\n\n")
        fh.write(f"Open ports: {sorted(result.open_ports.keys())}\n\n")
        fh.write("Findings:\n")
        for f in findings_sorted:
            fh.write(f"[{f.severity.upper()}] {f.title}\n    {f.detail}\n")

    with open(md_path, "w") as fh:
        fh.write(f"# Vulnerability Scan Report — {result.target}\n\n")
        fh.write(f"**Generated:** {datetime.datetime.now(datetime.timezone.utc).isoformat()}Z\n\n")
        fh.write(f"**Summary:** {counts['high']} high, {counts['medium']} medium, "
                 f"{counts['low']} low, {counts['info']} info\n\n")
        fh.write("## Open Ports\n\n")
        if result.open_ports:
            fh.write("| Port | Service | Banner (truncated) |\n|---|---|---|\n")
            for port, banner in sorted(result.open_ports.items()):
                clean_banner = banner.replace("\n", " ").replace("|", "/")[:80]
                fh.write(f"| {port} | {COMMON_PORTS.get(port, 'unknown')} | {clean_banner} |\n")
        else:
            fh.write("No open ports found.\n")
        fh.write("\n## Findings\n\n")
        for f in findings_sorted:
            fh.write(f"### [{f.severity.upper()}] {f.title}\n\n{f.detail}\n\n")

    return txt_path, md_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_ports_arg(arg):
    if arg == "common":
        return sorted(COMMON_PORTS.keys())
    ports = set()
    for chunk in arg.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="Mini vulnerability scanner for authorized security testing / learning.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Only scan systems you own or are explicitly authorized to test."
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("--ports", default="common",
                         help="'common' (default), a comma list (e.g. 22,80,443), "
                              "or a range (e.g. 1-1024)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port connect timeout in seconds")
    parser.add_argument("--workers", type=int, default=100, help="Concurrent scan threads")
    parser.add_argument("--output", default="vuln_report", help="Base filename for the report (no extension)")
    parser.add_argument("--i-have-authorization", action="store_true",
                         help="Confirm you are authorized to scan this target")
    args = parser.parse_args()

    if not args.i_have_authorization:
        print("Refusing to scan: pass --i-have-authorization once you have confirmed you own")
        print("this target or have explicit written permission to test it.")
        sys.exit(1)

    try:
        host_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Could not resolve host: {args.target}")
        sys.exit(1)

    ports = parse_ports_arg(args.ports)
    print(f"Scanning {args.target} ({host_ip}) — {len(ports)} ports, timeout={args.timeout}s ...")

    open_ports = run_port_scan(host_ip, ports, args.timeout, args.workers)
    findings = build_findings(host_ip, open_ports)

    result = ScanResult(target=f"{args.target} ({host_ip})", open_ports=open_ports, findings=findings)
    print_report(result)
    txt_path, md_path = write_reports(result, args.output)
    print(f"Reports written to:\n  {txt_path}\n  {md_path}")


if __name__ == "__main__":
    main()