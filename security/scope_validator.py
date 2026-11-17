from urllib.parse import urlsplit
import ipaddress


class ScopeValidationError(Exception):
    """Raised when a target is outside the authorized scope."""
    pass


def normalize_domain(domain):
    if not isinstance(domain, str) or not domain:
        raise ScopeValidationError("Invalid allowed domain.")

    if domain != domain.strip() or domain.endswith(".."):
        raise ScopeValidationError("Invalid domain format.")

    domain = domain[:-1] if domain.endswith(".") else domain

    try:
        ipaddress.ip_address(domain)
        raise ScopeValidationError(
            "IP addresses must be listed in allowed_ips."
        )
    except ValueError:
        pass

    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ScopeValidationError("Invalid domain format.")

    if len(domain) > 253:
        raise ScopeValidationError("Domain is too long.")

    labels = domain.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
        ):
            raise ScopeValidationError("Invalid domain format.")

    return domain


class ScopeValidator:
    def __init__(
        self,
        allowed_domains=None,
        allowed_ips=None,
        allow_subdomains=False
    ):
        self.allowed_domains = {
            normalize_domain(domain)
            for domain in (allowed_domains or [])
        }

        try:
            self.allowed_ips = {
                str(ipaddress.ip_address(ip))
                for ip in (allowed_ips or [])
            }
        except ValueError:
            raise ScopeValidationError("Invalid IP in allowed_ips.")

        self.allow_subdomains = allow_subdomains

    def validate(self, target):
        if not isinstance(target, str) or not target:
            raise ScopeValidationError("Target cannot be empty.")

        if target != target.strip() or any(c.isspace() for c in target):
            raise ScopeValidationError("Whitespace in target is not allowed.")

        try:
            parsed = urlsplit(target)

            if parsed.scheme not in ("http", "https"):
                raise ScopeValidationError(
                    "Only HTTP and HTTPS are allowed."
                )

            if not parsed.netloc or not parsed.hostname:
                raise ScopeValidationError("Invalid target hostname.")

            if "@" in parsed.netloc:
                raise ScopeValidationError(
                    "Credentials in target URLs are not allowed."
                )

            # Accessing port also checks its numeric range and format.
            _ = parsed.port

            hostname = parsed.hostname

        except ValueError as error:
            raise ScopeValidationError(
                f"Malformed target URL: {error}"
            )

        try:
            ip = str(ipaddress.ip_address(hostname))

            if ip in self.allowed_ips:
                return True

            raise ScopeValidationError(
                "IP address is outside authorized scope."
            )

        except ValueError:
            pass

        hostname = normalize_domain(hostname)

        for domain in self.allowed_domains:
            if hostname == domain:
                return True

            if (
                self.allow_subdomains
                and hostname.endswith("." + domain)
            ):
                return True

        raise ScopeValidationError(
            f"Domain '{hostname}' is outside authorized scope."
        )
