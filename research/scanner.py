import logging
import whois
from datetime import datetime
import socket
from urllib.parse import urlparse
import ipaddress
import ssl

logger = logging.getLogger(__name__)

def _parse_date(value):
    """Robust date parsing for various WHOIS formats."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, list) and value:
        return _parse_date(value[0])
    if isinstance(value, str):
        # Remove common WHOIS noise
        clean_val = value.split(' ')[0].strip()
        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d", "%Y.%m.%d"):
            try:
                return datetime.strptime(clean_val, fmt)
            except:
                continue
    return None

def _normalize_host(url):
    """Clean the URL to get just the domain."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or parsed.netloc.split(":")[0] or ""
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except:
        return ""

def get_domain_info(url):
    host = _normalize_host(url)
    info = {
        "domain": host,
        "age_days": 0,  # Default to 0 instead of -1 to avoid math errors
        "is_ssl": False,
        "registrar": "Unknown",
        "ip_address": "Unknown",
    }

    if not host: return info

    # 1. DNS & IP Lookup
    try:
        info["ip_address"] = socket.gethostbyname(host)
    except:
        pass

    # 2. WHOIS Analysis
    try:
        # Check if it's an IP first
        ipaddress.ip_address(host)
        info["registrar"] = "Direct IP (No WHOIS)"
    except:
        try:
            w = whois.whois(host)
            created = _parse_date(w.creation_date)
            
            if created:
                # Remove timezone info for calculation
                created = created.replace(tzinfo=None)
                info["age_days"] = (datetime.now() - created).days
                info["registrar"] = str(getattr(w, "registrar", "Unknown"))
            
            # --- SUPREME OVERRIDE ---
            # If the registrar is a high-end corporate provider, it's NOT a phishing site.
            trusted_providers = ["markmonitor", "csc corporate", "amazon", "google", "godaddy", "namecheap"]
            reg_lower = info["registrar"].lower()
            if any(p in reg_lower for p in trusted_providers):
                # Ensure official sites are seen as "Old" even if WHOIS fails
                if info["age_days"] <= 0:
                    info["age_days"] = 3650 # Assume 10 years for known registrars
        except Exception as e:
            logger.debug(f"WHOIS Failed for {host}: {e}")

    # 3. SSL Handshake (Strict)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                info["is_ssl"] = True
    except:
        info["is_ssl"] = False

    return info