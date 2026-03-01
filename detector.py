#!/usr/bin/env python3
"""
🎣 Phishing Detector — Core Engine
Features: ML + Rules + VirusTotal API + SQLite History
"""

import re
import math
import json
import time
import sqlite3
import hashlib
import urllib.parse
from datetime import datetime

# ─── Feature Extraction ──────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "ebay", "netflix", "password", "confirm", "wallet", "support",
    "suspended", "unusual", "alert", "urgent", "click", "free",
    "winner", "prize", "lucky", "limited", "offer", "webscr",
    "credential", "authenticate", "validate", "billing", "invoice",
]

TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "netflix.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "youtube.com",
    "wikipedia.org", "stackoverflow.com", "reddit.com",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".link", ".pw", ".cc", ".su", ".ws", ".info", ".biz",
]

SHORTENERS = [
    "bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rb.gy", "cutt.ly",
]


def extract_features(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        full   = url.lower()
    except Exception:
        domain, path, full = "", "", url.lower()

    clean_domain = re.sub(r"^www\.", "", domain)

    f = {}
    f["url_length"]               = len(url)
    f["domain_length"]            = len(domain)
    f["path_length"]              = len(path)
    f["num_dots"]                 = url.count(".")
    f["num_hyphens"]              = url.count("-")
    f["num_underscores"]          = url.count("_")
    f["num_slashes"]              = url.count("/")
    f["num_at"]                   = url.count("@")
    f["num_question"]             = url.count("?")
    f["num_equals"]               = url.count("=")
    f["num_ampersand"]            = url.count("&")
    f["num_percent"]              = url.count("%")
    f["num_digits"]               = sum(c.isdigit() for c in url)
    f["has_ip"]                   = int(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)))
    f["has_https"]                = int(url.startswith("https"))
    f["has_http"]                 = int(url.startswith("http://"))
    f["has_at_symbol"]            = int("@" in url)
    f["has_double_slash"]         = int("//" in path)
    f["has_port"]                 = int(bool(re.search(r":\d+", domain)))
    f["subdomain_count"]          = max(0, clean_domain.count("."))
    f["has_encoded_chars"]        = int("%" in url)
    f["suspicious_keyword_count"] = sum(kw in full for kw in SUSPICIOUS_KEYWORDS)
    f["has_brand_in_subdomain"]   = int(
        any(brand.split(".")[0] in domain.split(".")[0]
            for brand in TRUSTED_DOMAINS
            if clean_domain not in TRUSTED_DOMAINS)
    )
    f["suspicious_tld"]           = int(any(full.split("?")[0].endswith(t) for t in SUSPICIOUS_TLDS))
    f["domain_entropy"]           = _entropy(clean_domain.split(".")[0] if clean_domain else "")
    f["is_shortened"]             = int(any(s in full for s in SHORTENERS))
    return f


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def rule_based_score(features: dict, url: str) -> tuple:
    score, reasons = 0, []

    def add(pts, msg, category="general"):
        nonlocal score
        score += pts
        reasons.append({"pts": pts, "msg": msg, "category": category})

    f = features
    if f["has_ip"]:                         add(25, "IP address used instead of domain name", "structural")
    if f["has_at_symbol"]:                  add(20, "@ symbol redirects to different host", "structural")
    if f["has_brand_in_subdomain"]:         add(20, "Trusted brand name spoofed in subdomain", "spoofing")
    if f["suspicious_tld"]:                 add(15, "Free/suspicious TLD detected", "domain")
    if f["subdomain_count"] >= 3:           add(15, f"Excessive subdomains ({f['subdomain_count']})", "domain")
    if f["has_double_slash"]:               add(10, "Double slash redirection trick", "structural")
    if f["url_length"] > 75:               add(10, f"Very long URL ({f['url_length']} chars)", "length")
    if f["url_length"] > 100:              add(5,  f"Extremely long URL", "length")
    if f["num_hyphens"] >= 4:              add(10, f"Too many hyphens ({f['num_hyphens']})", "domain")
    if f["num_dots"] >= 5:                 add(8,  f"Too many dots ({f['num_dots']})", "domain")
    if f["suspicious_keyword_count"] >= 2:  add(15, f"Multiple suspicious keywords ({f['suspicious_keyword_count']})", "content")
    elif f["suspicious_keyword_count"] == 1: add(7, "Suspicious keyword found", "content")
    if f["domain_entropy"] > 3.8:           add(12, f"High domain entropy ({f['domain_entropy']:.2f}) — random-looking", "domain")
    if f["has_encoded_chars"]:              add(8,  "URL-encoded chars (obfuscation)", "structural")
    if f["is_shortened"]:                   add(15, "URL shortener hides real destination", "structural")
    if not f["has_https"]:                  add(8,  "No HTTPS — unencrypted", "ssl")
    if f["has_port"]:                       add(8,  "Non-standard port in URL", "structural")
    if f["num_digits"] > 10:               add(5,  f"Many digits in URL ({f['num_digits']})", "general")

    return min(score, 100), reasons


def train_model():
    try:
        from sklearn.ensemble import RandomForestClassifier
        import numpy as np
    except ImportError:
        return None

    phishing_urls = [
        "http://192.168.1.1/login/paypal/verify.php",
        "http://secure-paypal-login.tk/cmd=_s-xclick",
        "http://www.amazon.account-verify.ml/signin",
        "http://apple-id-suspended.xyz/verify?user=victim",
        "http://login.microsoft.com.evil.com/auth",
        "http://bit.ly/3xFrEe-Prize-Click-Now",
        "http://paypal-secure.account.update.cf/login",
        "http://203.0.113.5/banking/login.php?redirect=paypal",
        "http://google.com.phishing.tk/account/login",
        "http://verify-your-netflix.gq/signin?confirm=1",
        "http://support.apple.com.id-locked.ml/verify",
        "http://amazon-winner-prize-free.xyz/claim",
        "http://login-ebay-suspended-account.cf/signin",
        "http://secure.paypal.com.login.verify.ws/cmd",
        "http://192.168.0.1/admin/login?redirect=paypal.com",
        "http://update-your-banking-credentials.tk/auth",
        "http://credential-verify.top/microsoft/login.php",
        "http://win-free-iphone.click/claim?lucky=1",
        "http://password-reset.amazon-fake.ml/verify",
        "http://account-suspended.apple-id.xyz/unlock",
    ]
    legit_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/user/repo",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://stackoverflow.com/questions/123456",
        "https://docs.python.org/3/library/socket.html",
        "https://www.microsoft.com/en-us/windows",
        "https://www.linkedin.com/in/username",
        "https://twitter.com/user/status/123",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.paypal.com/signin",
        "https://appleid.apple.com/sign-in",
        "https://account.microsoft.com/account",
        "https://www.netflix.com/login",
        "https://www.ebay.com/signin",
        "https://mail.google.com/mail/u/0/",
        "https://www.facebook.com/login",
        "https://instagram.com/accounts/login",
        "https://secure.bankofamerica.com/login",
        "https://chase.com/personal/checking",
    ]

    X, y = [], []
    for url in phishing_urls:
        X.append(list(extract_features(url).values()))
        y.append(1)
    for url in legit_urls:
        X.append(list(extract_features(url).values()))
        y.append(0)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    return clf


# ─── VirusTotal Integration ───────────────────────────────────────

def check_virustotal(url: str, api_key: str) -> dict:
    """Submit URL to VirusTotal and get scan results."""
    import requests as req
    import base64

    if not api_key or api_key == "d736c5f7e5323ade2e05cca6e9be9388d734e013fa43eeab50ab3607a83fdda2":
        return {"error": "No API key configured", "available": False}

    try:
        headers = {"x-apikey": api_key}

        # Encode URL for VT API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = req.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )

        if resp.status_code == 404:
            # Submit for scanning
            scan = req.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            if scan.status_code != 200:
                return {"error": f"VT scan failed: {scan.status_code}", "available": False}
            time.sleep(3)
            resp = req.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=10
            )

        if resp.status_code != 200:
            return {"error": f"VT API error: {resp.status_code}", "available": False}

        data  = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        return {
            "available":    True,
            "malicious":    mal,
            "suspicious":   sus,
            "harmless":     stats.get("harmless", 0),
            "undetected":   stats.get("undetected", 0),
            "total":        total,
            "detection_rate": round((mal + sus) / total * 100, 1),
            "vt_verdict":   "MALICIOUS" if mal >= 3 else "SUSPICIOUS" if mal >= 1 or sus >= 3 else "CLEAN",
            "link":         f"https://www.virustotal.com/gui/url/{url_id}",
        }

    except Exception as e:
        return {"error": str(e), "available": False}


# ─── SQLite History ───────────────────────────────────────────────

def init_db(db_path="phishing_history.db"):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            url         TEXT,
            verdict     TEXT,
            final_score INTEGER,
            rule_score  INTEGER,
            ml_score    REAL,
            vt_malicious INTEGER,
            vt_total     INTEGER,
            reasons     TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(result: dict, db_path="phishing_history.db"):
    vt = result.get("virustotal", {})
    conn = sqlite3.connect(db_path)
    conn.execute("""
        INSERT INTO scans
        (timestamp, url, verdict, final_score, rule_score, ml_score, vt_malicious, vt_total, reasons)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        result["url"],
        result["verdict"],
        result["final_score"],
        result["rule_score"],
        result.get("ml_score"),
        vt.get("malicious", 0) if vt.get("available") else None,
        vt.get("total", 0)     if vt.get("available") else None,
        json.dumps([r["msg"] for r in result.get("reasons", [])]),
    ))
    conn.commit()
    conn.close()


def get_history(db_path="phishing_history.db", limit=50):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats(db_path="phishing_history.db"):
    conn = sqlite3.connect(db_path)
    total    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict='PHISHING'").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict='SUSPICIOUS'").fetchone()[0]
    safe     = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict='LIKELY SAFE'").fetchone()[0]
    avg      = conn.execute("SELECT AVG(final_score) FROM scans").fetchone()[0] or 0
    conn.close()
    return {
        "total": total, "phishing": phishing,
        "suspicious": suspicious, "safe": safe,
        "avg_score": round(avg, 1),
    }


# ─── Main Analyzer ───────────────────────────────────────────────

class PhishingDetector:
    def __init__(self, vt_api_key="", db_path="phishing_history.db"):
        self.vt_api_key = vt_api_key
        self.db_path    = db_path
        self.model      = train_model()
        init_db(db_path)

    def analyze(self, url: str, check_vt=False) -> dict:
        features              = extract_features(url)
        rule_score, reasons   = rule_based_score(features, url)

        ml_score, ml_label = None, None
        if self.model:
            import numpy as np
            prob     = self.model.predict_proba([list(features.values())])[0][1]
            ml_score = round(prob * 100, 1)
            ml_label = "PHISHING" if prob >= 0.5 else "LEGITIMATE"

        final_score = round(0.4 * rule_score + 0.6 * ml_score) if ml_score is not None else rule_score

        # VirusTotal
        vt_result = {}
        if check_vt and self.vt_api_key:
            vt_result = check_virustotal(url, self.vt_api_key)
            if vt_result.get("available") and vt_result["vt_verdict"] == "MALICIOUS":
                final_score = min(100, final_score + 20)

        final_score = min(100, final_score)

        if final_score >= 70:   verdict = "PHISHING"
        elif final_score >= 40: verdict = "SUSPICIOUS"
        else:                   verdict = "LIKELY SAFE"

        result = {
            "url":         url,
            "verdict":     verdict,
            "final_score": final_score,
            "rule_score":  rule_score,
            "ml_score":    ml_score,
            "ml_label":    ml_label,
            "reasons":     reasons,
            "features":    features,
            "virustotal":  vt_result,
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        save_scan(result, self.db_path)
        return result