import re
import socket
import os
import logging
import ipaddress
from urllib.parse import urlparse
from typing import Set, Optional
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

# --- 1. SUPREME WHITELIST (No CSV needed) ---
# These are the brands we protect from being cloned.
# If a URL is in this list, it's 100% safe.
# If a URL "looks" like these but isn't, it's a Clone.
PROTECTED_BRANDS = {
    "google.com": "Google",
    "facebook.com": "Facebook",
    "amazon.com": "Amazon",
    "reddit.com": "Reddit",
    "wikipedia.org": "Wikipedia",
    "youtube.com": "YouTube",
    "netflix.com": "Netflix",
    "paypal.com": "PayPal",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "github.com": "GitHub",
    "chatgpt.com": "OpenAI/ChatGPT"
}

def is_globally_trusted(url: str) -> bool:
    """
    Returns True if the domain is an exact match for an official brand.
    """
    try:
        if not url: return False
        parsed = urlparse(url.lower().strip() if "://" in url else f"http://{url}")
        host = parsed.hostname or parsed.netloc.split(":")[0] or ""
        domain = host.replace("www.", "")

        # Check exact domain or root domain (e.g., mail.google.com -> google.com)
        if domain in PROTECTED_BRANDS:
            return True
            
        parts = domain.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            if root in PROTECTED_BRANDS:
                return True
        return False
    except Exception:
        return False

def detect_clone(url: str) -> Optional[str]:
    """
    CLONE DETECTION:
    Checks if a suspicious URL is 'visually similar' to a protected brand.
    Example: 'amaz0n.com' vs 'amazon.com'
    """
    try:
        parsed = urlparse(url.lower().strip() if "://" in url else f"http://{url}")
        host = parsed.hostname or parsed.netloc.split(":")[0] or ""
        current_domain = host.replace("www.", "").split('.')[0] # Get 'amaz0n' from 'amaz0n.com'
        
        # If it's already on the trusted list, it's not a clone
        if is_globally_trusted(url):
            return None

        for brand_url, brand_name in PROTECTED_BRANDS.items():
            brand_domain = brand_url.split('.')[0] # Get 'amazon'
            
            # Fuzzy matching: Check how similar the strings are (0.0 to 1.0)
            similarity = SequenceMatcher(None, current_domain, brand_domain).ratio()
            
            # If similarity is very high (e.g. 85%+) or brand name is hidden inside
            # (e.g. 'secure-login-google.com'), flag it as a clone.
            if similarity >= 0.82 or (brand_domain in current_domain and len(current_domain) > len(brand_domain)):
                return brand_name
                
        return None
    except Exception:
        return None

def extract_features(url: str):
    """
    Return a 30-feature vector compatible with the model.
    """
    features = []
    try:
        url = (url or "").lower().strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc.split(":")[0] or ""
        domain = host

        # 1. IP Address detection
        try:
            ipaddress.ip_address(domain)
            features.append(-1) 
        except:
            features.append(1) 

        # 2. URL Length
        url_len = len(url)
        features.append(1 if url_len < 54 else (0 if url_len <= 75 else -1))

        # 3. Shortening services
        match = re.search(r"(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|buff\.ly)", url)
        features.append(-1 if match else 1)

        # 4. @ symbol
        features.append(-1 if "@" in url else 1)

        # 5. Redirect '//'
        features.append(-1 if url.rfind("//") > 7 else 1)

        # 6. Prefix/Suffix '-' in domain
        features.append(-1 if "-" in domain else 1)

        # 7. Subdomains
        dots = domain.count(".")
        features.append(1 if dots <= 2 else (0 if dots == 3 else -1))

        # 8. HTTPS
        features.append(1 if parsed.scheme == "https" else -1)

        # Fill to 30 features
        while len(features) < 30:
            features.append(1)

        return features
    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        return [1] * 30