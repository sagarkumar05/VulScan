import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import DEFAULT_PORTS, PORT_SCAN_TIMEOUT, MAX_THREADS

# port service name mapping
PORT_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPCBind",
    135:  "MS-RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
}


def scan_ports(host: str, logger: logging.Logger,
               ports: list = None) -> dict:
    if ports is None:
        ports = DEFAULT_PORTS
    logger.info(f"[PortScan] Scanning {len(ports)} ports on {host} (threads={MAX_THREADS})")
    open_ports = []

    def check_port(port: int) -> dict | None:
        """Single port check — None return karta hai agar closed hai."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown")
                return {"port": port, "status": "open", "service": service}
        except Exception:
            pass
        return None

    # Parallel scanning with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                logger.info(f"[PortScan] OPEN → Port {res['port']} ({res['service']})")

    # Sort by port number for cleaner output
    open_ports.sort(key=lambda x: x["port"])

    total_open = len(open_ports)
    logger.info(f"[PortScan] Done. {total_open}/{len(ports)} ports open.")

    # Risk flag for dangerous open ports , Add more dandegrious ports in this list if you want to check more ports 
    dangerous_ports = [21, 23, 135, 139, 445, 3389, 5900]
    dangerous_found = [p for p in open_ports if p["port"] in dangerous_ports]
    if dangerous_found:
        logger.warning(
            f"[PortScan] ⚠ Dangerous ports open: {[p['port'] for p in dangerous_found]}"
        )

    return {
        "open_ports":    open_ports,
        "total_scanned": len(ports),
        "total_open":    total_open,
        "dangerous_open": [p["port"] for p in dangerous_found],
    }
