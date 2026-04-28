REQUEST_TIMEOUT = 10          # HTTP request timeout
PORT_SCAN_TIMEOUT = 1         # TCP connect timeout per port
SSL_TIMEOUT = 10              # SSL handshake timeout

# Port scanner settings 
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888
]
MAX_THREADS = 100             # Parallel threads for port scanning

#Add Sub Customdomain
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp",
    "pop", "ns1", "webdisk", "ns2", "cpanel", "whm",
    "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin",
    "forum", "news", "vpn", "ns3", "mail2", "new",
    "mysql", "old", "lists", "support", "mobile", "mx",
    "static", "docs", "beta", "shop", "api", "cdn",
    "staging", "app", "portal", "demo", "remote"
]

# SQL Injection payloads , UPDATE: if payload is test then add more payloads to this list
SQL_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR '1'='1' --",
    "' OR 1=1 --", "\" OR \"1\"=\"1", "' OR 'x'='x",
    "1; DROP TABLE users--", "' UNION SELECT NULL--",
    "' AND 1=0 UNION SELECT NULL,NULL--"
]

# SQL error signatures to detect in response
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "postgresql error",
    "ora-01756", "ora-00933",
    "syntax error or access violation",
    "sqlite3.operationalerror",
    "pg::syntaxerror"
]

# XSS payloads , if Custom XSS payloads test then add more payloads to this list
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>"
]

# Report setting
REPORT_DIR = "reports"        #if you want to require report then change path
LOG_DIR = "logs"              # if you want to require logst then change path

# http header report request setting
HEADERS = {
    "User-Agent": "VulnScanner/1.0 (B.Tech Final Year Security Tool)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}
