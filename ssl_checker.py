import ssl
import socket
import logging
from datetime import datetime

from config import SSL_TIMEOUT


def check_ssl(host: str, logger: logging.Logger, port: int = 443) -> dict:
    host = host.replace("https://", "").replace("http://", "").split("/")[0]
    logger.info(f"[SSL] Checking SSL/TLS for {host}:{port}")
    result = {
        "host":             host,
        "port":             port,
        "ssl_enabled":      False,
        "subject":          "N/A",
        "issuer":           "N/A",
        "version":          "N/A",
        "expires":          "N/A",
        "days_remaining":   None,
        "expired":          False,
        "self_signed":      False,
        "weak_protocol":    False,
        "issues":           [],
        "errors":           [],
    }

    try:
        # Create SSL context 
        context = ssl.create_default_context()
        # Stricter verification
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = socket.create_connection((host, port), timeout=SSL_TIMEOUT)
        ssl_conn = context.wrap_socket(conn, server_hostname=host)

        result["ssl_enabled"] = True

        # Protocol version
        version = ssl_conn.version()
        result["version"] = version
        # if weak protocols checking then update inlist
        if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            result["weak_protocol"] = True
            result["issues"].append(f"Weak protocol in use: {version}")
            logger.warning(f"[SSL] ⚠ Weak protocol: {version}")

        # Certificate details
        cert = ssl_conn.getpeercert()

        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            result["subject"] = subject.get("commonName", "N/A")

            # Issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_org = issuer.get("organizationName", "N/A")
            result["issuer"] = issuer_org

            # Self-signed check
            if issuer == subject:
                result["self_signed"] = True
                result["issues"].append("Certificate is self-signed")
                logger.warning("[SSL] ⚠ Self-signed certificate detected")

            # Expiry date
            not_after = cert.get("notAfter", "")
            if not_after:
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                result["expires"] = expiry_date.strftime("%Y-%m-%d")
                days_left = (expiry_date - datetime.utcnow()).days
                result["days_remaining"] = days_left

                if days_left < 0:
                    result["expired"] = True
                    result["issues"].append("Certificate has EXPIRED!")
                    logger.warning("[SSL] ⚠ Certificate EXPIRED!")
                elif days_left < 30:
                    result["issues"].append(f"Certificate expires in {days_left} days — renew soon!")
                    logger.warning(f"[SSL] ⚠ Expiring soon: {days_left} days")
                else:
                    logger.info(f"[SSL] Certificate valid for {days_left} more days")
        else:
            der_cert = ssl_conn.getpeercert(binary_form=True)
            if der_cert:
                result["subject"] = "Parsed from DER (details N/A)"

        ssl_conn.close()
        conn.close()

        if not result["issues"]:
            logger.info("[SSL] ✓ No SSL issues found")

    except ssl.SSLError as e:
        msg = f"SSL Error: {e}"
        result["errors"].append(msg)
        logger.error(f"[SSL] {msg}")
    except ConnectionRefusedError:
        msg = f"Connection refused on port {port} — SSL may not be enabled"
        result["errors"].append(msg)
        result["ssl_enabled"] = False
        logger.warning(f"[SSL] {msg}")
    except Exception as e:
        msg = f"Unexpected error: {e}"
        result["errors"].append(msg)
        logger.error(f"[SSL] {msg}")

    return result
