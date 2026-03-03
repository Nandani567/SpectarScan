# # research/utils.py
# import re
# from urllib.parse import urlparse
# import socket
# import pandas as pd 
# def extract_features(url):
#     features = []
#     url = url.lower().strip()
#     if not url.startswith(('http', 'https')): url = 'https://' + url
    
#     parsed = urlparse(url)
#     domain = parsed.netloc
    
#     # 1. IP Address (UCI: -1 Phish, 1 Legit -> Your Model: 0 Phish, 1 Legit)
#     try:
#         socket.inet_aton(domain)
#         features.append(0) 
#     except:
#         features.append(1) 

#     # 2. URL Length (UCI: <54 Legit, 54-75 Suspicious, >75 Phish)
#     url_len = len(url)
#     if url_len < 54: features.append(1)
#     elif 54 <= url_len <= 75: features.append(0) # In your 0/1 mapping, 0 is the "lower/danger" side
#     else: features.append(0)

    


#     # 3. Shortening (0 Phish, 1 Legit)
#     match = re.search(r'bit\.ly|goo\.gl|tinyurl|t\.co', url)
#     features.append(0 if match else 1)

#     # 4. Symbol @ (0 Phish, 1 Legit)
#     features.append(0 if "@" in url else 1)

#     # 5. Redirect // (0 Phish, 1 Legit)
#     features.append(0 if url.rfind('//') > 7 else 1)

#     # 6. Prefix/Suffix '-' in Domain (0 Phish, 1 Legit)
#     features.append(0 if '-' in domain else 1)

#     # 7. Subdomains (1 Legit, 0 Phish)
#     dots = domain.count('.')
#     features.append(1 if dots <= 2 else 0)

#     # 8. HTTPS (1 Legit, 0 Phish)
#     features.append(1 if parsed.scheme == 'https' else 0)

#     # IMPORTANT: The UCI dataset has 30 specific features. 
#     # If your model sees a bunch of "1"s (Legitimate) for the rest, 
#     # it will stop flagging ChatGPT.
#     while len(features) < 30:
#         features.append(1) # Default the unknown features to 'Legitimate'

#     return features


import re
import socket
import pandas as pd
from urllib.parse import urlparse
import os

# --- GLOBAL REPUTATION LOGIC ---
# Get the directory where utils.py is located to find the csv
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, 'top-1m.csv')

try:
    # We use 'header=None' if your CSV doesn't have column names
    # Common format is: 1,google.com
    df = pd.read_csv(CSV_PATH, names=['rank', 'domain'])
    TOP_SITES = set(df['domain'].tolist())
    print(f"✅ Successfully loaded {len(TOP_SITES)} trusted domains.")
except Exception as e:
    TOP_SITES = set()
    print(f"⚠️ Warning: top-1m.csv not found or error loading. Trusted check disabled: {e}")

def is_globally_trusted(url):
    """Checks if the root domain is in the Top 1 Million list."""
    try:
        parsed = urlparse(url.lower().strip() if "://" in url else f"http://{url}")
        domain = parsed.netloc.replace("www.", "")
        
        # Check the exact domain and the root (e.g., en.wikipedia.org -> wikipedia.org)
        parts = domain.split('.')
        if domain in TOP_SITES:
            return True
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            if root in TOP_SITES:
                return True
        return False
    except:
        return False

# --- FEATURE EXTRACTION LOGIC ---
def extract_features(url):
    features = []
    url = url.lower().strip()
    if not url.startswith(('http', 'https')): url = 'https://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # 1. IP Address
    try:
        socket.inet_aton(domain)
        features.append(-1) 
    except:
        features.append(1) 

    # 2. URL Length
    url_len = len(url)
    if url_len < 54: features.append(1)
    elif 54 <= url_len <= 75: features.append(0)
    else: features.append(-1)

    # 3. Shortening
    match = re.search(r'bit\.ly|goo\.gl|tinyurl|t\.co', url)
    features.append(-1 if match else 1)

    # 4. Symbol @
    features.append(-1 if "@" in url else 1)

    # 5. Redirect //
    features.append(-1 if url.rfind('//') > 7 else 1)

    # 6. Prefix/Suffix '-'
    features.append(-1 if '-' in domain else 1)

    # 7. Subdomains
    dots = domain.count('.')
    if dots <= 2: features.append(1)
    elif dots == 3: features.append(0)
    else: features.append(-1)

    # 8. HTTPS
    features.append(1 if parsed.scheme == 'https' else -1)

    # Fill to 30 features for the UCI model
    while len(features) < 30:
        features.append(1)

    return features