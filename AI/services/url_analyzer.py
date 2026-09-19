import re
from urllib.parse import urlparse

URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9-]+\.(?:xyz|top|online|club|site|work|tech|gq|cf|ml|tk|link|click|info|cc)/[^\s<>"]*', re.IGNORECASE)

URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly', 'rb.gy', 'v.ht', 'shorturl.at'}
SUSPICIOUS_TLDS = {'.xyz', '.top', '.online', '.club', '.site', '.work', '.tech', '.gq', '.cf', '.ml', '.tk', '.cc', '.icu', '.click', '.fit', '.buzz'}
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'kyc', 'bank', 'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'upi', 'claim', 'reward', 'lottery', 'free', 'prize', 'account', 'security', 'secure', 'winner', 'aadhaar', 'pan', 'refund', 'tax']

def analyze_urls(text):
    """
    Extracts URLs from text and performs rule-based safety heuristics.
    Returns a dict with url_count, detected_urls array, and safety summary.
    """
    if not text:
        return {"url_count": 0, "urls": [], "has_urls": False, "summary": "No URL detected."}
    
    matches = URL_REGEX.findall(text)
    # Deduplicate while preserving order
    unique_urls = list(dict.fromkeys(matches))
    
    if not unique_urls:
        return {"url_count": 0, "urls": [], "has_urls": False, "summary": "No URL detected."}
    
    analyzed_urls = []
    
    for raw_url in unique_urls:
        res = evaluate_single_url(raw_url)
        analyzed_urls.append({
            "url": raw_url,
            "domain": res["domain"],
            "https_status": res["is_https"],
            "is_shortened": res["is_shortened"],
            "observations": res["indicators"]
        })
        
    return {
        "url_count": len(analyzed_urls),
        "urls": analyzed_urls,
        "has_urls": True,
        "summary": f"{len(analyzed_urls)} link(s) detected. Potentially suspicious characteristics evaluated."
    }


def evaluate_single_url(raw_url):
    """
    Comprehensive single-URL inspection for the Link Safety Analysis module.
    Returns risk status, indicators, explanation, safety recommendations, and next steps.
    """
    if not raw_url or not raw_url.strip():
        return {
            "url": "",
            "domain": "",
            "is_https": False,
            "is_shortened": False,
            "risk_status": "LOW",
            "risk_badge": "success",
            "indicators": ["No URL provided."],
            "explanation": "Please enter a valid web URL or domain name to begin analysis.",
            "recommendations": ["Ensure you type the full website address accurately."],
            "next_steps": ["Enter an HTTP/HTTPS link to inspect."]
        }

    raw_url = raw_url.strip()
    formatted_url = raw_url
    if not raw_url.startswith(('http://', 'https://')):
        formatted_url = 'http://' + raw_url

    parsed = urlparse(formatted_url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    indicators = []
    risk_score = 0

    is_https = parsed.scheme == 'https'
    if not is_https:
        risk_score += 25
        indicators.append("Unencrypted HTTP protocol: Data transmitted in plain text without SSL/TLS encryption.")

    # Raw IP check
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$')
    if ip_pattern.match(domain):
        risk_score += 45
        indicators.append("Direct IP address host: Uses numerical IP rather than a verified domain name (common phishing tactic).")

    # Shortened URL check
    is_shortened = domain in URL_SHORTENERS or any(domain.endswith('.' + s) for s in URL_SHORTENERS)
    if is_shortened:
        risk_score += 30
        indicators.append("URL shortener detected: Conceals actual destination host and redirects through intermediary service.")

    # High-risk TLD check
    tld_detected = None
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            tld_detected = tld
            risk_score += 35
            indicators.append(f"High-risk top-level domain ({tld}): Cheap or free domain extension heavily abused by phishing operators.")
            break

    # Excessive subdomains (spoofing)
    domain_parts = domain.split('.')
    if len(domain_parts) > 3 and not ip_pattern.match(domain):
        risk_score += 25
        indicators.append("Deep subdomain nesting: Often used to imitate legitimate institutional domains (e.g. sbi.co.in.scamdomain.com).")

    # Suspicious keywords in domain or path
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain or kw in path]
    if found_keywords:
        risk_score += 30
        indicators.append(f"High-risk brand / urgency keywords in URL: '{', '.join(found_keywords)}'.")

    # Determine risk level
    if risk_score >= 50:
        risk_status = "HIGH RISK"
        risk_badge = "danger"
        explanation = (
            f"The link '{raw_url}' exhibits strong indicators of a malicious, phishing, or spoofed URL. "
            f"Multiple red flags were identified including "
            f"{'unencrypted communication, ' if not is_https else ''}"
            f"{'raw IP hosting, ' if ip_pattern.match(domain) else ''}"
            f"{'high-risk domain extension, ' if tld_detected else ''}"
            f"and high-risk keywords."
        )
        recommendations = [
            "DO NOT click or visit this URL.",
            "DO NOT enter your username, password, OTP, bank account number, or UPI PIN on this site.",
            "If already clicked, immediately close the browser tab and clear recent browser data.",
            "Scan your device with an updated antivirus or mobile security software."
        ]
        next_steps = [
            "Block the sender who provided this link on SMS, WhatsApp, or email.",
            "Report this malicious link to Google Safe Browsing: safebrowsing.google.com.",
            "Submit the phishing link to the National Cybercrime Portal (cybercrime.gov.in)."
        ]
    elif risk_score >= 25:
        risk_status = "SUSPICIOUS"
        risk_badge = "warning"
        explanation = (
            f"The link '{raw_url}' displays suspicious structural patterns that warrant extreme caution. "
            f"It may be a masked redirect, unencrypted endpoint, or low-reputation domain."
        )
        recommendations = [
            "Proceed with extreme caution; avoid submitting any sensitive information.",
            "Manually navigate to the service's official website rather than clicking this link.",
            "Inspect the browser address bar for valid SSL padlock before interacting."
        ]
        next_steps = [
            "Verify the link's legitimacy with the official organization's support desk.",
            "Do not download any files, APKs, or profile configurations prompted by this URL."
        ]
    else:
        risk_status = "LOW RISK"
        risk_badge = "success"
        explanation = (
            f"The link '{raw_url}' uses standard encrypted protocols and does not trigger common phishing heuristics."
        )
        recommendations = [
            "Always ensure the browser address bar matches the intended destination company exactly.",
            "Never enter confidential credentials (OTPs or UPI PINs) on any third-party website."
        ]
        next_steps = [
            "You may access the destination, maintaining standard internet hygiene."
        ]

    if not indicators:
        indicators = ["Standard URL structure with valid protocol; no immediate high-risk anomalies detected."]

    return {
        "url": raw_url,
        "domain": domain or raw_url,
        "is_https": is_https,
        "is_shortened": is_shortened,
        "risk_status": risk_status,
        "risk_badge": risk_badge,
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "next_steps": next_steps
    }
