#!/usr/bin/env python3
"""
Broken Link Hijacking (BLH) Scanner v4.0
For legitimate bug bounty / security auditing purposes only.

Changelog v4.0:
  [FIX]  SERVFAIL + REFUSED kini dideteksi sebagai "orphaned_ns" (CRITICAL)
         — kasus 6connex.us yang sebelumnya terlewat kini terdeteksi dengan benar
  [FIX]  DNS resolver kini menggunakan public DNS (8.8.8.8, 1.1.1.1, 9.9.9.9)
         sebagai fallback, tidak lagi bergantung resolver lokal/VPN
  [NEW]  check_dns_status(): bedakan NXDOMAIN vs SERVFAIL vs REFUSED vs TIMEOUT
  [NEW]  check_orphaned_ns(): deteksi NS record pointing ke zone yang sudah
         dihapus dari provider (ghost domain / orphaned NS → CRITICAL)
  [NEW]  DNS result cache (TTL 5 menit) — hindari resolve berulang domain sama
  [NEW]  WHOIS auto-check untuk domain HIGH/CRITICAL (--whois flag)
  [NEW]  Warna progress bar per subdomain:
           Merah  = ada CRITICAL atau HIGH finding
           Kuning = ada MEDIUM finding
           Hijau  = bersih / hanya LOW/INFO
  [NEW]  print_finding() tampilkan CNAME chain + NS list untuk takeover
  [NEW]  Severity CRITICAL untuk orphaned NS
  [NEW]  --resume: lanjut scan dari checkpoint jika interrupted
  [NEW]  --whois: aktifkan WHOIS lookup (butuh python-whois)
  [NEW]  by_takeover breakdown di summary

Changelog v3.1:
  [FIX]  False positive NXDOMAIN — domain induk masih aktif diturunkan ke LOW
  [NEW]  check_dangling_cname(), check_parent_domain_controlled()
  [NEW]  TAKEOVER_FINGERPRINTS (35+ cloud services)

Changelog v3.0:
  [FIX]  Race condition, per-thread session, retry logic
  [NEW]  HTML report, progress counter, severity filter, deduplication

Usage:
    pip install requests beautifulsoup4 tldextract colorama dnspython
    pip install python-whois   # opsional untuk --whois

    python blh_scanner.py --file subdomains.txt
    python blh_scanner.py --url https://target.com --depth 2 --threads 5
    python blh_scanner.py --file subdomains.txt --html-output report.html --whois
    python blh_scanner.py --file subdomains.txt --severity-filter CRITICAL HIGH
    python blh_scanner.py --file subdomains.txt --resume state.json
"""

import argparse
import json
import os
import re
import socket
import sys
import time
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import tldextract
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Config ───────────────────────────────────────────────────────────────────

VERSION = "4.0"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BLH-Scanner/4.0; Bug Bounty Audit)"
}
REQUEST_TIMEOUT  = 12
CRAWL_DELAY      = 0.5
DEBUG            = False
MAX_RETRIES      = 2
RETRY_BACKOFF    = 1.0
MAX_EXT_PER_PAGE = 0
SEVERITY_FILTER  = None
WHOIS_ENABLED    = False

# [NEW v4.0] Public DNS — tidak bergantung resolver lokal/VPN
PUBLIC_DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# [NEW v4.0] DNS cache
_dns_cache      = {}
DNS_CACHE_TTL   = 300   # 5 menit
_dns_cache_lock = threading.Lock()

LINK_ATTRS = {
    "a":      ["href"],
    "script": ["src"],
    "link":   ["href"],
    "iframe": ["src"],
    "img":    ["src", "data-src"],
    "source": ["src"],
    "form":   ["action"],
}

SKIP_LOGIN    = "requires_login"
SKIP_NOHTML   = "non_html_response"
SKIP_TIMEOUT  = "timeout_or_error"
SKIP_REDIRECT = "redirected_out_of_scope"
SKIP_EMPTY    = "no_links_found"

# ─── Severity color system ────────────────────────────────────────────────────
#  Progress bar: CRITICAL/HIGH=merah, MEDIUM=kuning, LOW/INFO=hijau

SEV_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.GREEN,
    "INFO":     Fore.CYAN,
}

SEV_BAR = {
    "CRITICAL": Back.RED    + Fore.WHITE + Style.BRIGHT,
    "HIGH":     Back.RED    + Fore.WHITE,
    "MEDIUM":   Back.YELLOW + Fore.BLACK,
    "LOW":      Back.GREEN  + Fore.BLACK,
    "INFO":     Back.CYAN   + Fore.BLACK,
}

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def severity_color(sev: str) -> str:
    return SEV_COLOR.get(sev, Fore.WHITE)


def bar_color_for_findings(findings: list) -> str:
    """
    Tentukan warna progress bar dari severity tertinggi finding.
    CRITICAL/HIGH → merah | MEDIUM → kuning | LOW/INFO/kosong → hijau
    """
    if not findings:
        return Fore.GREEN
    best = min(findings, key=lambda f: SEV_RANK.get(f["severity"], 99))
    sev  = best["severity"]
    if sev in ("CRITICAL", "HIGH"):
        return Fore.RED
    if sev == "MEDIUM":
        return Fore.YELLOW
    return Fore.GREEN

# ─── Social media definitions ─────────────────────────────────────────────────

SOCIAL_PLATFORMS = {
    "twitter_x": {
        "domains": ["twitter.com", "x.com"],
        "pattern": r"(?:twitter\.com|x\.com)/(?!intent|share|hashtag|search|home|explore|notifications|messages|i/)([A-Za-z0-9_]{1,50})/?(?:\?.*)?$",
        "label":   "Twitter/X",
        "check":   "x",
    },
    "instagram": {
        "domains": ["instagram.com", "www.instagram.com"],
        "pattern": r"instagram\.com/(?!p/|reel/|explore/|stories/|tv/)([A-Za-z0-9_.]{1,30})/?(?:\?.*)?$",
        "label":   "Instagram",
        "check":   "instagram",
    },
    "facebook": {
        "domains": ["facebook.com", "www.facebook.com", "fb.com"],
        "pattern": r"(?:facebook\.com|fb\.com)/(?!sharer|share|dialog|pages/category|photo|video|events|groups/(?!.*[0-9]))([A-Za-z0-9._-]{1,80})/?(?:\?.*)?$",
        "label":   "Facebook",
        "check":   "facebook",
    },
    "youtube": {
        "domains": ["youtube.com", "www.youtube.com", "youtu.be"],
        "pattern": r"youtube\.com/(?:c/|channel/|@|user/)?([A-Za-z0-9_@.-]{2,100})/?(?:\?.*)?$",
        "label":   "YouTube",
        "check":   "youtube",
    },
    "linkedin": {
        "domains": ["linkedin.com", "www.linkedin.com"],
        "pattern": r"linkedin\.com/(?:in|company)/([A-Za-z0-9_-]{2,100})/?(?:\?.*)?$",
        "label":   "LinkedIn",
        "check":   "linkedin",
    },
    "github": {
        "domains": ["github.com"],
        "pattern": r"github\.com/([A-Za-z0-9_-]{1,100})/?(?:\?.*)?$",
        "label":   "GitHub",
        "check":   "github",
    },
    "tiktok": {
        "domains": ["tiktok.com", "www.tiktok.com"],
        "pattern": r"tiktok\.com/@([A-Za-z0-9_.]{2,50})/?(?:\?.*)?$",
        "label":   "TikTok",
        "check":   "tiktok",
    },
}

DEAD_ACCOUNT_STATUSES = {k: [404] for k in SOCIAL_PLATFORMS}

UNVERIFIABLE_PLATFORMS = {
    "linkedin":  [999, 429, 403],
    "instagram": [403, 429],
    "facebook":  [403, 429],
    "tiktok":    [403, 429],
}

DEAD_ACCOUNT_SIGNALS = {
    "x":         ["this account doesn't exist", "sorry, that page doesn't exist",
                  "account suspended", "user not found"],
    "instagram": ["sorry, this page isn't available", "the link you followed may be broken"],
    "facebook":  ["this content isn't available", "the page you requested cannot be displayed",
                  "this page isn't available"],
    "youtube":   ["this channel doesn't exist", "this page isn't available"],
    "linkedin":  ["this profile is not available", "page not found",
                  "this linkedin page isn't available"],
    "github":    ["not found", "this is not the web page you are looking for"],
    "tiktok":    ["couldn't find this account", "user not found"],
}

# ─── Takeover fingerprints ────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "amazonaws.com":         "AWS S3 / CloudFront",
    "s3.amazonaws.com":      "AWS S3",
    "cloudfront.net":        "AWS CloudFront",
    "elasticbeanstalk.com":  "AWS Elastic Beanstalk",
    "awsdns-34.com":         "AWS Route53",
    "awsdns-28.net":         "AWS Route53",
    "awsdns-14.org":         "AWS Route53",
    "awsdns-06.co.uk":       "AWS Route53",
    "awsdns":                "AWS Route53",
    "github.io":             "GitHub Pages",
    "githubusercontent.com": "GitHub",
    "heroku.com":            "Heroku",
    "herokudns.com":         "Heroku",
    "herokuapp.com":         "Heroku",
    "fastly.net":            "Fastly CDN",
    "fastlylb.net":          "Fastly CDN",
    "azurewebsites.net":     "Azure Web Apps",
    "trafficmanager.net":    "Azure Traffic Manager",
    "azurefd.net":           "Azure Front Door",
    "cloudapp.net":          "Azure Cloud",
    "netlify.app":           "Netlify",
    "netlify.com":           "Netlify",
    "vercel.app":            "Vercel",
    "now.sh":                "Vercel (legacy)",
    "surge.sh":              "Surge.sh",
    "bitbucket.io":          "Bitbucket Pages",
    "zendesk.com":           "Zendesk",
    "helpscoutdocs.com":     "HelpScout",
    "ghost.io":              "Ghost",
    "pantheonsite.io":       "Pantheon",
    "wpengine.com":          "WP Engine",
    "kinsta.cloud":          "Kinsta",
    "myshopify.com":         "Shopify",
    "squarespace.com":       "Squarespace",
    "webflow.io":            "Webflow",
    "tumblr.com":            "Tumblr",
    "readme.io":             "ReadMe",
    "gitbook.io":            "GitBook",
    "eventsair.com":         "EventsAir",
    "hubspot.net":           "HubSpot",
    "hs-sites.com":          "HubSpot",
    "intercom.help":         "Intercom",
    "statuspage.io":         "Atlassian Statuspage",
    "freshdesk.com":         "Freshdesk",
    "dnsimple.com":          "DNSimple",
    "cloudflare.com":        "Cloudflare",
}

# ─── Thread-safe state ────────────────────────────────────────────────────────

_print_lock    = threading.Lock()
_seen_lock     = threading.Lock()
_findings_lock = threading.Lock()
_counter_lock  = threading.Lock()
_dedup_lock    = threading.Lock()

_progress_done  = 0
_progress_total = 0
_dedup_urls     = set()

# ─── Logging ──────────────────────────────────────────────────────────────────

def info(msg):
    with _print_lock:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")

def ok(msg):
    with _print_lock:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def warn(msg):
    with _print_lock:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def err(msg):
    with _print_lock:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def dbg(msg):
    if DEBUG:
        with _print_lock:
            print(f"{Fore.WHITE}[D]{Style.RESET_ALL} {msg}")

# ─── Print finding ────────────────────────────────────────────────────────────

def print_finding(finding):
    """
    [v4.0] Bar warna sesuai severity:
      CRITICAL/HIGH → background merah
      MEDIUM        → background kuning
      LOW           → background hijau
    Tampilkan juga CNAME chain, NS list, WHOIS jika tersedia.
    """
    sev       = finding["severity"]
    color     = severity_color(sev)
    bar_bg    = SEV_BAR.get(sev, Fore.WHITE)
    is_social = finding.get("type") == "social_media"
    ttype     = finding.get("takeover_type", "")

    with _print_lock:
        print(f"\n  {bar_bg} {'━'*60} {Style.RESET_ALL}")

        if is_social:
            print(f"  {bar_bg} [{sev}] 🔗 SOCIAL MEDIA BLH – {finding.get('platform','')} {Style.RESET_ALL}")
            print(f"  {color}  Username : @{finding.get('username','?')}{Style.RESET_ALL}")
        elif sev == "CRITICAL":
            print(f"  {bar_bg} [CRITICAL] ☠  GHOST DOMAIN / ORPHANED NS {Style.RESET_ALL}")
        elif ttype == "dangling_cname":
            print(f"  {bar_bg} [HIGH] ⚠  DANGLING CNAME – SUBDOMAIN TAKEOVER {Style.RESET_ALL}")
        elif ttype == "expired_domain":
            print(f"  {bar_bg} [HIGH] ⚠  EXPIRED DOMAIN – BISA DIDAFTARKAN ULANG {Style.RESET_ALL}")
        else:
            print(f"  {bar_bg} [{sev}] BLH CANDIDATE {Style.RESET_ALL}")

        print(f"  {color}  URL      : {finding['url']}{Style.RESET_ALL}")
        print(f"  {color}  Alasan   : {finding['reason']}{Style.RESET_ALL}")
        print(f"  {color}  Tag      : <{finding['tag']} {finding['attr']}=...>{Style.RESET_ALL}")
        print(f"  {color}  DNS      : {finding.get('dns_status', '?')}{Style.RESET_ALL}")

        if finding.get("cname_target"):
            svc = finding.get("takeover_service", "unknown")
            print(f"  {color}  CNAME    : {finding['domain']} → {finding['cname_target']} [{svc}]{Style.RESET_ALL}")

        if finding.get("ns_records"):
            for ns in finding["ns_records"][:4]:
                print(f"  {color}  NS       : {ns} → REFUSED/unreachable{Style.RESET_ALL}")

        if finding.get("whois_expiry"):
            print(f"  {color}  WHOIS    : Expiry={finding['whois_expiry']}  Registrar={finding.get('whois_registrar','?')}{Style.RESET_ALL}")

        print(f"  {color}  Ditemukan: {finding['found_on']}{Style.RESET_ALL}")
        print(f"  {color}  Subdomain: {finding['source_subdomain']}{Style.RESET_ALL}")
        print(f"  {bar_bg} {'━'*60} {Style.RESET_ALL}\n")

# ─── Progress bar ─────────────────────────────────────────────────────────────

def print_progress(scanned_url: str, elapsed: float, ext_count: int,
                   finding_count: int, sub_findings: list):
    """
    [v4.0] Progress bar berwarna:
      🔴 Merah  = CRITICAL atau HIGH
      🟡 Kuning = MEDIUM
      🟢 Hijau  = bersih / LOW / INFO
    """
    global _progress_done
    with _counter_lock:
        _progress_done += 1
        done  = _progress_done
        total = _progress_total

    bar_color = bar_color_for_findings(sub_findings)

    c = sum(1 for f in sub_findings if f["severity"] == "CRITICAL")
    h = sum(1 for f in sub_findings if f["severity"] == "HIGH")
    m = sum(1 for f in sub_findings if f["severity"] == "MEDIUM")
    l = sum(1 for f in sub_findings if f["severity"] == "LOW")
    i = sum(1 for f in sub_findings if f["severity"] == "INFO")

    pct    = done / total if total else 1
    filled = int(20 * pct)
    bar    = "█" * filled + "░" * (20 - filled)

    with _print_lock:
        print(
            f"  {bar_color}[{bar}]{Style.RESET_ALL} "
            f"{bar_color}[{done}/{total}]{Style.RESET_ALL} "
            f"{scanned_url[:38]:<38} "
            f"ext={ext_count:>4}  "
            f"{Fore.RED + Style.BRIGHT}C:{c}{Style.RESET_ALL} "
            f"{Fore.RED}H:{h}{Style.RESET_ALL} "
            f"{Fore.YELLOW}M:{m}{Style.RESET_ALL} "
            f"{Fore.GREEN}L:{l}{Style.RESET_ALL} "
            f"{Fore.CYAN}I:{i}{Style.RESET_ALL} "
            f"({elapsed:.1f}s)"
        )

# ─── URL / domain helpers ─────────────────────────────────────────────────────

def normalise_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw

def get_base_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def is_same_scope(url: str, scope_domains: set) -> bool:
    return get_base_domain(url) in scope_domains

# ─── HTTP fetch ───────────────────────────────────────────────────────────────

def fetch(url: str, session: requests.Session, custom_headers=None):
    h        = {**HEADERS, **(custom_headers or {})}
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            r = session.get(url, headers=h, timeout=REQUEST_TIMEOUT,
                            allow_redirects=True, verify=False)
            dbg(f"fetch {url} → HTTP {r.status_code}")
            return r
        except requests.exceptions.Timeout:
            last_exc = "timeout"
            dbg(f"fetch {url} → TIMEOUT ({attempt+1}/{MAX_RETRIES})")
        except requests.RequestException as e:
            last_exc = str(e)
            dbg(f"fetch {url} → ERROR ({attempt+1}/{MAX_RETRIES}): {e}")
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_BACKOFF)
    return None

# ─── Extract links ────────────────────────────────────────────────────────────

def extract_links(html: str, page_url: str) -> list:
    soup  = BeautifulSoup(html, "html.parser")
    links = []
    for tag, attrs in LINK_ATTRS.items():
        for element in soup.find_all(tag):
            for attr in attrs:
                raw = element.get(attr, "").strip()
                if not raw or raw.startswith(("javascript:", "mailto:", "data:", "#")):
                    continue
                absolute = urljoin(page_url, raw)
                if urlparse(absolute).scheme not in ("http", "https"):
                    continue
                links.append({"url": absolute, "tag": tag, "attr": attr,
                               "context": str(element)[:200]})
    return links

# ─── Social media detection ───────────────────────────────────────────────────

def detect_social_platform(url: str):
    hostname = urlparse(url).netloc.lower().lstrip("www.")
    for key, platform in SOCIAL_PLATFORMS.items():
        for domain in platform["domains"]:
            if hostname in (domain, domain.lstrip("www.")):
                match = re.search(platform["pattern"], url, re.IGNORECASE)
                if match:
                    username = match.group(1).rstrip("/")
                    if username.lower() in ("about","contact","help","legal","privacy",
                                            "terms","policy","home","login","signup",
                                            "register","feed"):
                        return None
                    return key, platform, username
    return None


def check_social_account(url, platform_key, username, session):
    browser_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36")
    resp = fetch(url, session, custom_headers={"User-Agent": browser_ua})
    if resp is None:
        return False, None, "Koneksi gagal – tidak bisa diverifikasi"

    status = resp.status_code
    body   = resp.text.lower()

    if status in UNVERIFIABLE_PLATFORMS.get(platform_key, []):
        return False, status, f"HTTP {status} – platform memblokir verifikasi otomatis"
    if status in DEAD_ACCOUNT_STATUSES.get(platform_key, [404]):
        return True, status, f"HTTP {status} – akun tidak ditemukan / suspended"
    for signal in DEAD_ACCOUNT_SIGNALS.get(platform_key, []):
        if signal in body:
            return True, status, f"Halaman mengindikasikan akun tidak ada: \"{signal}\""
    return False, status, "Akun masih aktif"

# ─── DNS helpers ──────────────────────────────────────────────────────────────

def _make_resolver():
    if not DNS_AVAILABLE:
        return None
    r              = dns.resolver.Resolver()
    r.nameservers  = PUBLIC_DNS_RESOLVERS
    r.timeout      = 5
    r.lifetime     = 8
    return r


def check_dns_status(hostname: str) -> dict:
    """
    [NEW v4.0] Cek status DNS dengan public resolver.
    Membedakan: ok | nxdomain | servfail | refused | timeout | noanswer
    Hasil di-cache TTL 5 menit.
    """
    with _dns_cache_lock:
        if hostname in _dns_cache:
            cached, ts = _dns_cache[hostname]
            if time.time() - ts < DNS_CACHE_TTL:
                dbg(f"DNS cache hit: {hostname} → {cached['status']}")
                return cached

    result = {"status": "unknown", "resolves": False, "ip": None, "error": None}

    if not DNS_AVAILABLE:
        try:
            ip     = socket.getaddrinfo(hostname, None)[0][4][0]
            result = {"status": "ok", "resolves": True, "ip": ip, "error": None}
        except socket.gaierror as e:
            result = {"status": "nxdomain", "resolves": False, "ip": None, "error": str(e)}
        with _dns_cache_lock:
            _dns_cache[hostname] = (result, time.time())
        return result

    resolver = _make_resolver()
    try:
        answers = resolver.resolve(hostname, 'A')
        result  = {"status": "ok", "resolves": True,
                   "ip": str(answers[0]), "error": None}

    except dns.resolver.NXDOMAIN:
        result = {"status": "nxdomain", "resolves": False, "ip": None, "error": "NXDOMAIN"}

    except dns.resolver.NoAnswer:
        result = {"status": "noanswer", "resolves": False, "ip": None, "error": "NoAnswer"}

    except dns.resolver.NoNameservers as e:
        # Semua NS REFUSED atau tidak bisa dijangkau — ini kasus 6connex.us!
        err_lower = str(e).lower()
        status    = "refused" if "refused" in err_lower else "servfail"
        result    = {"status": status, "resolves": False, "ip": None,
                     "error": f"NoNameservers: {e}"}

    except dns.exception.Timeout:
        result = {"status": "timeout", "resolves": False, "ip": None, "error": "Timeout"}

    except Exception as e:
        result = {"status": "unknown", "resolves": False, "ip": None, "error": str(e)}

    dbg(f"DNS {hostname} → {result['status']}")
    with _dns_cache_lock:
        _dns_cache[hostname] = (result, time.time())
    return result


def check_orphaned_ns(hostname: str) -> dict:
    """
    [NEW v4.0] Deteksi orphaned NS / ghost domain.
    Scenario: domain terdaftar + NS pointing ke provider, tapi zone sudah dihapus.
    Semua NS jawab REFUSED → siapapun bisa buat zone baru di provider itu.

    Returns: {is_orphaned, ns_records, provider, detail}
    """
    if not DNS_AVAILABLE:
        return {"is_orphaned": False, "ns_records": [], "provider": None,
                "detail": "dnspython tidak tersedia"}

    resolver = _make_resolver()
    ext      = tldextract.extract(hostname)
    parent   = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    ns_recs  = []
    provider = None

    try:
        answers = resolver.resolve(parent, 'NS')
        ns_recs = [str(r).rstrip(".") for r in answers]
        dbg(f"NS untuk {parent}: {ns_recs}")
        for ns in ns_recs:
            ns_lower = ns.lower()
            for fp, svc in TAKEOVER_FINGERPRINTS.items():
                if fp in ns_lower:
                    provider = svc
                    break
            if provider:
                break
    except Exception as e:
        dbg(f"NS lookup error untuk {parent}: {e}")
        return {"is_orphaned": False, "ns_records": [], "provider": None,
                "detail": f"NS lookup error: {e}"}

    if not ns_recs:
        return {"is_orphaned": False, "ns_records": [], "provider": None,
                "detail": "Tidak ada NS record"}

    # Query langsung ke setiap NS — apakah semua REFUSED?
    refused = 0
    checked = 0
    for ns_host in ns_recs[:4]:
        checked += 1
        try:
            ns_ip = socket.gethostbyname(ns_host)
            ns_res = dns.resolver.Resolver()
            ns_res.nameservers = [ns_ip]
            ns_res.timeout     = 4
            ns_res.lifetime    = 6
            ns_res.resolve(parent, 'SOA')
            dbg(f"NS {ns_host} merespons SOA — bukan orphaned")
            return {"is_orphaned": False, "ns_records": ns_recs,
                    "provider": provider, "detail": f"NS {ns_host} masih aktif"}
        except dns.resolver.NoNameservers:
            refused += 1
            dbg(f"NS {ns_host} → REFUSED")
        except dns.exception.Timeout:
            refused += 1
            dbg(f"NS {ns_host} → TIMEOUT")
        except socket.gaierror:
            refused += 1
            dbg(f"NS {ns_host} → tidak bisa di-resolve")
        except Exception as e:
            dbg(f"NS {ns_host} → error: {e}")

    if checked > 0 and refused == checked:
        detail = (
            f"Semua {refused} NS mengembalikan REFUSED/unreachable. "
            f"Provider terdeteksi: {provider or 'unknown'}. "
            f"Zone kemungkinan dihapus dari {provider or 'provider'} "
            f"tapi NS di registrar belum diupdate — ghost domain!"
        )
        return {"is_orphaned": True, "ns_records": ns_recs,
                "provider": provider, "detail": detail}

    return {"is_orphaned": False, "ns_records": ns_recs, "provider": provider,
            "detail": f"{refused}/{checked} NS REFUSED"}


def check_dangling_cname(hostname: str) -> tuple:
    """Cek dangling CNAME. Returns (cname_target, service) atau (None, None)."""
    if not DNS_AVAILABLE:
        return None, None

    resolver = _make_resolver()
    target   = hostname
    chain    = []
    try:
        for _ in range(10):
            try:
                answers = resolver.resolve(target, 'CNAME')
                cname   = str(answers[0].target).rstrip(".")
                chain.append(cname)
                target  = cname
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
            except dns.exception.DNSException:
                break
    except Exception:
        return None, None

    if not chain:
        return None, None

    final = chain[-1]
    dbg(f"CNAME chain: {hostname} → {' → '.join(chain)}")

    if check_dns_status(final)["resolves"]:
        return None, None

    service = None
    for fp, svc in TAKEOVER_FINGERPRINTS.items():
        if fp in final.lower():
            service = svc
            break

    dbg(f"DANGLING CNAME: {hostname} → {final} [{service}]")
    return final, service


def check_parent_domain_controlled(hostname: str) -> bool:
    """Cek apakah domain induk masih punya SOA/NS. True = masih dikontrol."""
    ext    = tldextract.extract(hostname)
    parent = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    if parent == hostname:
        return False

    if not DNS_AVAILABLE:
        return check_dns_status(parent)["resolves"]

    resolver = _make_resolver()
    try:
        resolver.resolve(parent, 'SOA')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        try:
            resolver.resolve(parent, 'NS')
            return True
        except Exception:
            return False
    except Exception:
        return False

# ─── WHOIS ────────────────────────────────────────────────────────────────────

def do_whois(hostname: str) -> dict:
    """[NEW v4.0] WHOIS lookup — hanya jika --whois aktif."""
    if not WHOIS_ENABLED or not WHOIS_AVAILABLE:
        return {}
    ext    = tldextract.extract(hostname)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    try:
        w      = whois_lib.whois(domain)
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        expiry_str = expiry.strftime("%Y-%m-%d") if expiry else "unknown"
        registrar  = getattr(w, 'registrar', 'unknown') or 'unknown'
        status     = getattr(w, 'status', [])
        if isinstance(status, str):
            status = [status]
        return {"whois_expiry": expiry_str, "whois_registrar": registrar,
                "whois_status": status[:3]}
    except Exception as e:
        dbg(f"WHOIS error untuk {domain}: {e}")
        return {}

# ─── BLH check ────────────────────────────────────────────────────────────────

def check_blh_candidate(link: dict, session: requests.Session):
    """
    [v4.0] Severity matrix:

      Orphaned NS (semua NS REFUSED, zone hilang)  → CRITICAL
      Dangling CNAME → cloud service               → HIGH
      Domain induk expired / tidak ada SOA         → HIGH
      Domain induk masih aktif (NXDOMAIN saja)     → LOW  (bukan takeover)
      HTTP 404 / 410                               → MEDIUM
      Koneksi gagal                                → LOW
      HTTP 403                                     → INFO  (anti-bot)
    """
    url = link["url"]

    # Prioritas 1: sosial media
    social = detect_social_platform(url)
    if social:
        platform_key, platform_info, username = social
        is_dead, status, reason = check_social_account(
            url, platform_key, username, session)
        if is_dead:
            f = {
                "type": "social_media", "platform": platform_info["label"],
                "username": username, "url": url,
                "domain": urlparse(url).netloc, "tag": link["tag"],
                "attr": link["attr"], "status_code": status,
                "dns_status": "ok", "resolves": True, "severity": "HIGH",
                "reason": reason, "takeover_type": None,
                "found_on": link.get("found_on", ""),
                "source_subdomain": link.get("source_subdomain", ""),
                "context": link["context"],
            }
            f.update(do_whois(urlparse(url).netloc))
            return f
        return None

    # Prioritas 2: domain biasa
    hostname = urlparse(url).netloc.split(":")[0]
    dns_info = check_dns_status(hostname)
    resolves = dns_info["resolves"]
    dns_st   = dns_info["status"]
    resp     = fetch(url, session)
    status   = resp.status_code if resp else None

    cname_target  = None
    takeover_type = None
    takeover_svc  = None
    ns_records    = []
    extra         = {}

    if not resolves:
        if dns_st in ("servfail", "refused"):
            # [NEW v4.0] Cek orphaned NS
            orphan = check_orphaned_ns(hostname)
            if orphan["is_orphaned"]:
                severity      = "CRITICAL"
                takeover_type = "orphaned_ns"
                ns_records    = orphan["ns_records"]
                prov          = orphan["provider"] or "unknown"
                reason        = (
                    f"GHOST DOMAIN – Orphaned NS: semua NS REFUSED/unreachable. "
                    f"Zone dihapus dari {prov} tapi NS registrar masih menunjuk kesana. "
                    f"Siapapun bisa buat hosted zone baru di {prov}."
                )
                extra = do_whois(hostname)
            else:
                severity      = "LOW"
                takeover_type = "servfail_unverified"
                reason        = (
                    f"DNS {dns_st.upper()} – {orphan['detail']}. "
                    f"Tidak terkonfirmasi sebagai takeover, cek manual."
                )
        else:
            # NXDOMAIN atau noanswer — cek dangling CNAME
            cname_target, takeover_svc = check_dangling_cname(hostname)
            if cname_target:
                severity      = "HIGH"
                takeover_type = "dangling_cname"
                reason        = (
                    f"Dangling CNAME: {hostname} → {cname_target} "
                    f"[{takeover_svc or 'unknown'}] – target tidak resolve"
                )
                extra = do_whois(hostname)
            else:
                parent_ok = check_parent_domain_controlled(hostname)
                if parent_ok:
                    severity      = "LOW"
                    takeover_type = "none"
                    reason        = (
                        f"Subdomain NXDOMAIN – domain induk masih dikontrol pemilik. "
                        f"Broken link biasa, bukan risiko takeover."
                    )
                else:
                    severity      = "HIGH"
                    takeover_type = "expired_domain"
                    reason        = (
                        f"Domain NXDOMAIN dan domain induk tidak punya SOA – "
                        f"kemungkinan expired, bisa didaftarkan ulang."
                    )
                    extra = do_whois(hostname)

    elif status in (404, 410):
        severity, reason = "MEDIUM", f"HTTP {status} – resource sudah tidak ada"
    elif status is None:
        severity, reason = "LOW", "Koneksi gagal – resource tidak dapat dijangkau"
    elif status == 403:
        severity, reason = "INFO", "HTTP 403 – akses ditolak (kemungkinan anti-bot)"
    else:
        return None

    if SEVERITY_FILTER and severity not in SEVERITY_FILTER:
        return None

    finding = {
        "type": "broken_link", "url": url, "domain": hostname,
        "tag": link["tag"], "attr": link["attr"],
        "status_code": status, "dns_status": dns_st,
        "resolves": resolves, "severity": severity, "reason": reason,
        "takeover_type": takeover_type,
        "found_on": link.get("found_on", ""),
        "source_subdomain": link.get("source_subdomain", ""),
        "context": link["context"],
    }
    if cname_target:
        finding["cname_target"]     = cname_target
        finding["takeover_service"] = takeover_svc or "unknown"
    if ns_records:
        finding["ns_records"] = ns_records
    if extra:
        finding.update(extra)
    return finding

# ─── Diagnose subdomain ───────────────────────────────────────────────────────

def diagnose_subdomain(url: str, session: requests.Session) -> dict:
    result = {"url": url, "skip_reason": None, "detail": "", "final_url": ""}
    try:
        r = session.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                        allow_redirects=True, verify=False)
        result.update({"status_code": r.status_code, "final_url": r.url,
                        "content_type": r.headers.get("Content-Type", "")})
        ct = result["content_type"]

        if get_base_domain(r.url) != get_base_domain(url):
            result["skip_reason"] = SKIP_REDIRECT
            result["detail"]      = f"Redirect ke {r.url}"
            return result
        if "text/html" not in ct:
            result["skip_reason"] = SKIP_NOHTML
            result["detail"]      = f"Content-Type: {ct}"
            return result

        login_signals = ["login","sign in","signin","authenticate",
                         "unauthorized","access denied","sso","please log in"]
        matched = [s for s in login_signals if s in r.text.lower()]
        if r.status_code in (401, 403) or matched:
            result["skip_reason"] = SKIP_LOGIN
            result["detail"]      = f"HTTP {r.status_code} | {matched}"
            return result

        soup  = BeautifulSoup(r.text, "html.parser")
        links = [el.get(attr,"") for tag, attrs in LINK_ATTRS.items()
                 for el in soup.find_all(tag) for attr in attrs
                 if el.get(attr,"").strip()
                 and not el.get(attr,"").startswith(("javascript:","mailto:","#","data:"))]
        if not links:
            result["skip_reason"] = SKIP_EMPTY
            result["detail"]      = "Tidak ada static link – kemungkinan SPA/JS-heavy"
            return result

        result["total_links"] = len(links)
        result["detail"]      = f"{len(links)} link ditemukan, tapi semua internal"
        return result

    except requests.exceptions.Timeout:
        result["skip_reason"] = SKIP_TIMEOUT
        result["detail"]      = "Request timeout"
        return result
    except Exception as e:
        result["skip_reason"] = SKIP_TIMEOUT
        result["detail"]      = str(e)
        return result

# ─── Crawler ──────────────────────────────────────────────────────────────────

def crawl_and_check(start_url, max_depth, session, scope_domains,
                    global_seen_ext, all_findings_ref):
    queue         = deque([(start_url, 0)])
    visited       = set()
    ext_count     = 0
    finding_count = 0

    while queue:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        resp = fetch(url, session)
        if not resp:
            continue
        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            continue
        if resp.status_code in (401, 403):
            continue
        if get_base_domain(resp.url) not in scope_domains:
            continue

        time.sleep(CRAWL_DELAY)
        links       = extract_links(resp.text, resp.url)
        ext_on_page = 0
        dbg(f"page {url} → {len(links)} links")

        for link in links:
            lurl = link["url"]
            if is_same_scope(lurl, scope_domains):
                clean = lurl.split("?")[0].split("#")[0]
                if clean not in visited:
                    queue.append((clean, depth + 1))
            else:
                if MAX_EXT_PER_PAGE > 0 and ext_on_page >= MAX_EXT_PER_PAGE:
                    continue
                with _seen_lock:
                    if lurl in global_seen_ext:
                        continue
                    global_seen_ext.add(lurl)

                ext_count   += 1
                ext_on_page += 1
                link["found_on"]         = url
                link["source_subdomain"] = start_url

                time.sleep(CRAWL_DELAY)
                finding = check_blh_candidate(link, session)
                if finding:
                    with _dedup_lock:
                        if finding["url"] in _dedup_urls:
                            continue
                        _dedup_urls.add(finding["url"])
                    finding_count += 1
                    print_finding(finding)
                    with _findings_lock:
                        all_findings_ref.append(finding)

    return ext_count, finding_count

# ─── Thread worker ────────────────────────────────────────────────────────────

def scan_one(url, depth, scope_domains, global_seen, all_findings_ref):
    t0      = time.time()
    session = requests.Session()
    ec, fc  = crawl_and_check(url, depth, session, scope_domains,
                               global_seen, all_findings_ref)
    return url, ec, fc, time.time() - t0

# ─── Resume state ─────────────────────────────────────────────────────────────

def load_resume_state(path: str) -> set:
    if not path or not os.path.exists(path):
        return set()
    try:
        with open(path) as f:
            data = json.load(f)
        done = set(data.get("completed", []))
        ok(f"Resume: {len(done)} subdomain sudah di-scan, dilewati.")
        return done
    except Exception as e:
        warn(f"Gagal load resume state: {e}")
        return set()


def save_resume_state(path: str, completed: list, findings: list):
    if not path:
        return
    try:
        with open(path, "w") as f:
            json.dump({"completed": completed,
                       "findings_count": len(findings),
                       "saved_at": datetime.utcnow().isoformat()}, f, indent=2)
    except Exception as e:
        dbg(f"Gagal simpan resume state: {e}")

# ─── HTML report ──────────────────────────────────────────────────────────────

def generate_html_report(report: dict, output_path: str):
    findings  = report["findings"]
    summary   = report["summary"]
    scan_info = report["scan_info"]

    SEV_HTML_COLOR = {
        "CRITICAL": ("#cc0000", "#fff"),
        "HIGH":     ("#ff4d4d", "#fff"),
        "MEDIUM":   ("#ffaa00", "#111"),
        "LOW":      ("#44cc44", "#111"),
        "INFO":     ("#4dc3ff", "#111"),
    }

    rows = ""
    for f in findings:
        sev        = f["severity"]
        bg, fg     = SEV_HTML_COLOR.get(sev, ("#888", "#fff"))
        badge      = (f'<span style="background:{bg};color:{fg};padding:3px 10px;'
                      f'border-radius:4px;font-size:12px;font-weight:bold">{sev}</span>')
        ttype      = f.get("takeover_type","")
        ftype      = "🔗 Social" if f.get("type") == "social_media" else "🔗 Broken"
        ttype_badge = ""
        if ttype and ttype not in ("none",""):
            ttype_badge = (f'<br><span style="font-size:10px;color:{bg};font-weight:bold">'
                           f'⚠ {ttype.replace("_"," ").upper()}</span>')
        extra_info = ""
        if f.get("cname_target"):
            extra_info += f'<br><small style="color:#aaa">CNAME → {f["cname_target"]} [{f.get("takeover_service","")}]</small>'
        if f.get("ns_records"):
            extra_info += f'<br><small style="color:#aaa">NS: {", ".join(f["ns_records"][:2])}</small>'
        if f.get("whois_expiry"):
            extra_info += f'<br><small style="color:#ffaa00">Expiry: {f["whois_expiry"]} | {f.get("whois_registrar","")}</small>'

        rows += f"""
        <tr style="border-left:4px solid {bg}">
          <td>{badge}{ttype_badge}</td>
          <td>{ftype}</td>
          <td style="word-break:break-all">
            <a href="{f['url']}" target="_blank">{f['url'][:75]}</a>{extra_info}
          </td>
          <td style="font-size:12px">{f.get('platform', f.get('domain',''))}</td>
          <td style="font-size:12px">{f.get('dns_status', f.get('status_code','–'))}</td>
          <td style="font-size:12px">{f['reason'][:120]}</td>
          <td style="font-size:11px;word-break:break-all">{f['found_on'][:55]}</td>
        </tr>"""

    platform_rows = "".join(
        f"<tr><td>{p}</td><td>{c}</td></tr>"
        for p, c in summary.get("by_platform", {}).items()
    )
    takeover_rows = "".join(
        f"<tr><td>{t.replace('_',' ').title()}</td><td>{c}</td></tr>"
        for t, c in summary.get("by_takeover", {}).items()
        if t not in ("none",) and c > 0
    )

    crit = summary.get("critical", 0)
    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>BLH Scanner v4.0 – Report</title>
<style>
  *    {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:'Segoe UI',sans-serif; background:#080808;
         color:#e0e0e0; padding:24px }}
  h1   {{ color:#00d4ff; margin-bottom:4px; font-size:1.7em }}
  h2   {{ color:#999; border-bottom:1px solid #222; padding-bottom:6px;
         margin:24px 0 12px }}
  .card{{ background:#111; border:1px solid #1e1e1e; border-radius:10px;
         padding:18px; margin:10px 0 }}
  .stat-grid{{ display:flex; gap:12px; flex-wrap:wrap }}
  .stat{{ background:#161616; border-radius:8px; padding:14px 18px;
         min-width:108px; text-align:center; border:1px solid #222 }}
  .stat .num{{ font-size:2em; font-weight:bold }}
  .stat .lbl{{ font-size:0.72em; color:#666; margin-top:4px }}
  .crit{{ color:#cc0000 }} .high{{ color:#ff4d4d }}
  .med {{ color:#ffaa00 }} .low {{ color:#44cc44 }}
  .inf {{ color:#4dc3ff }}
  table{{ width:100%; border-collapse:collapse; font-size:13px }}
  th   {{ background:#161616; color:#777; padding:9px 8px; text-align:left;
         border-bottom:2px solid #2a2a2a; position:sticky; top:0; z-index:1 }}
  td   {{ padding:8px; border-bottom:1px solid #161616; vertical-align:top }}
  tr:hover td{{ background:#131313 }}
  a    {{ color:#4dc3ff; text-decoration:none }}
  a:hover{{ text-decoration:underline }}
  input {{ background:#161616; border:1px solid #2a2a2a; color:#eee;
          padding:7px 12px; border-radius:6px; width:300px; font-size:13px }}
  select{{ background:#161616; border:1px solid #2a2a2a; color:#eee;
          padding:7px 10px; border-radius:6px; font-size:13px }}
  .toolbar{{ display:flex; align-items:center; gap:8px; margin-bottom:14px; flex-wrap:wrap }}
  #countLabel{{ color:#555; font-size:12px }}
</style>
</head>
<body>
<h1>🔍 BLH Scanner v4.0 — Laporan Bug Bounty</h1>
<div class="card" style="font-size:13px;color:#666">
  <b style="color:#bbb">Timestamp:</b> {scan_info['timestamp']} &nbsp;|&nbsp;
  <b style="color:#bbb">Depth:</b> {scan_info['depth']} &nbsp;|&nbsp;
  <b style="color:#bbb">Threads:</b> {scan_info['threads']} &nbsp;|&nbsp;
  <b style="color:#bbb">v{scan_info.get('version','4.0')}</b><br>
  <b style="color:#bbb">Targets:</b> {', '.join(scan_info['targets'][:6])}{'...' if len(scan_info['targets'])>6 else ''}
</div>

<h2>Ringkasan</h2>
<div class="stat-grid">
  <div class="stat"><div class="num">{summary['total_findings']}</div><div class="lbl">Total</div></div>
  <div class="stat"><div class="num crit">{crit}</div><div class="lbl">CRITICAL</div></div>
  <div class="stat"><div class="num high">{summary['high']}</div><div class="lbl">HIGH</div></div>
  <div class="stat"><div class="num med">{summary['medium']}</div><div class="lbl">MEDIUM</div></div>
  <div class="stat"><div class="num low">{summary['low']}</div><div class="lbl">LOW</div></div>
  <div class="stat"><div class="num inf">{summary.get('info',0)}</div><div class="lbl">INFO</div></div>
  <div class="stat"><div class="num">{summary['social_media_findings']}</div><div class="lbl">Social Media</div></div>
  <div class="stat"><div class="num">{summary['broken_link_findings']}</div><div class="lbl">Broken Link</div></div>
  <div class="stat"><div class="num">{summary['total_subdomains']}</div><div class="lbl">Subdomain</div></div>
</div>

{"<h2>Social Media per Platform</h2><div class='card'><table><tr><th>Platform</th><th>Jumlah</th></tr>" + platform_rows + "</table></div>" if platform_rows else ""}
{"<h2>Takeover Type Breakdown</h2><div class='card'><table><tr><th>Type</th><th>Jumlah</th></tr>" + takeover_rows + "</table></div>" if takeover_rows else ""}

<h2>Semua Findings ({len(findings)})</h2>
<div class="card">
  <div class="toolbar">
    <input type="text" id="searchInput" onkeyup="filterTable()"
           placeholder="🔍 Filter URL, domain, alasan...">
    <select id="sevFilter" onchange="filterTable()">
      <option value="">Semua severity</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
      <option value="INFO">INFO</option>
    </select>
    <select id="typeFilter" onchange="filterTable()">
      <option value="">Semua tipe</option>
      <option value="Social">Social Media</option>
      <option value="Broken">Broken Link</option>
    </select>
    <select id="takoverFilter" onchange="filterTable()">
      <option value="">Semua takeover</option>
      <option value="orphaned">Orphaned NS</option>
      <option value="dangling">Dangling CNAME</option>
      <option value="expired">Expired Domain</option>
    </select>
    <span id="countLabel"></span>
  </div>
  <table id="findingsTable">
    <thead>
      <tr>
        <th style="width:145px">Severity</th>
        <th style="width:85px">Tipe</th>
        <th>URL</th>
        <th style="width:130px">Domain</th>
        <th style="width:85px">DNS/HTTP</th>
        <th>Alasan</th>
        <th style="width:170px">Ditemukan di</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<script>
function filterTable() {{
  const q   = document.getElementById("searchInput").value.toLowerCase();
  const sev = document.getElementById("sevFilter").value.toLowerCase();
  const typ = document.getElementById("typeFilter").value.toLowerCase();
  const tov = document.getElementById("takoverFilter").value.toLowerCase();
  let vis   = 0;
  document.querySelectorAll("#findingsTable tbody tr").forEach(r => {{
    const t = r.innerText.toLowerCase();
    const show = (!q||t.includes(q)) && (!sev||t.includes(sev))
              && (!typ||t.includes(typ)) && (!tov||t.includes(tov));
    r.style.display = show ? "" : "none";
    if (show) vis++;
  }});
  document.getElementById("countLabel").textContent = vis + " finding ditampilkan";
}}
filterTable();
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

# ─── File loader ──────────────────────────────────────────────────────────────

def load_subdomains(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        err(f"File tidak ditemukan: {filepath}")
        sys.exit(1)
    urls = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            u = normalise_url(line)
            if u:
                urls.append(u)
    ok(f"Loaded {len(urls)} subdomain(s) dari {filepath}")
    return urls

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global DEBUG, CRAWL_DELAY, MAX_EXT_PER_PAGE
    global SEVERITY_FILTER, WHOIS_ENABLED, _progress_total

    parser = argparse.ArgumentParser(
        description=f"BLH Scanner v{VERSION} – Ghost Domain + Takeover + Social Media"
    )
    parser.add_argument("--url",              help="Single target URL")
    parser.add_argument("--file",             help="File daftar subdomain")
    parser.add_argument("--depth",            type=int,   default=2)
    parser.add_argument("--threads",          type=int,   default=3)
    parser.add_argument("--delay",            type=float, default=0.5)
    parser.add_argument("--output",           default="blh_report.json")
    parser.add_argument("--html-output",      default=None)
    parser.add_argument("--max-ext-per-page", type=int, default=0)
    parser.add_argument("--severity-filter",  nargs="+", default=None,
                        choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"])
    parser.add_argument("--whois",            action="store_true",
                        help="Aktifkan WHOIS untuk HIGH/CRITICAL (pip install python-whois)")
    parser.add_argument("--resume",           default=None,
                        help="File state JSON untuk resume scan")
    parser.add_argument("--debug",            action="store_true")
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("Harus menyertakan --url atau --file")

    DEBUG            = args.debug
    CRAWL_DELAY      = args.delay
    MAX_EXT_PER_PAGE = args.max_ext_per_page
    SEVERITY_FILTER  = set(args.severity_filter) if args.severity_filter else None
    WHOIS_ENABLED    = args.whois

    targets = []
    if args.file:
        targets.extend(load_subdomains(args.file))
    if args.url:
        targets.append(normalise_url(args.url))
    targets = list(dict.fromkeys(targets))

    completed_prev = load_resume_state(args.resume)
    if completed_prev:
        targets = [t for t in targets if t not in completed_prev]
        info(f"Sisa target setelah resume: {len(targets)}")

    _progress_total = len(targets)
    scope_domains   = {get_base_domain(u) for u in targets}
    platforms_str   = ", ".join(p["label"] for p in SOCIAL_PLATFORMS.values())
    filter_str      = ", ".join(SEVERITY_FILTER) if SEVERITY_FILTER else "ALL"

    dns_str = (Fore.GREEN + "✔ aktif – public DNS " + str(PUBLIC_DNS_RESOLVERS) + Style.RESET_ALL
               if DNS_AVAILABLE
               else Fore.RED + "✘ nonaktif – pip install dnspython" + Style.RESET_ALL)
    whois_str = (Fore.GREEN + "✔ aktif" + Style.RESET_ALL
                 if (WHOIS_ENABLED and WHOIS_AVAILABLE)
                 else Fore.YELLOW + "✘ nonaktif (tambah --whois)" + Style.RESET_ALL
                 if not WHOIS_ENABLED
                 else Fore.RED + "✘ pip install python-whois" + Style.RESET_ALL)

    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║   Broken Link Hijacking (BLH) Scanner v4.0           ║
║   Ghost Domain + Subdomain Takeover + Social Media   ║
║   For authorized bug bounty use only                 ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
  Targets    : {len(targets)} subdomain(s)
  Depth      : {args.depth}  /  Threads : {args.threads}  /  Delay: {args.delay}s
  Retries    : {MAX_RETRIES}x  /  DNS cache TTL: {DNS_CACHE_TTL}s
  DNS        : {dns_str}
  WHOIS      : {whois_str}
  Resume     : {args.resume or '–'}
  Output     : {args.output}  /  HTML: {args.html_output or '–'}
  Ext/page   : {'unlimited' if MAX_EXT_PER_PAGE==0 else MAX_EXT_PER_PAGE}
  Severity   : {filter_str}
  Scope      : {', '.join(sorted(scope_domains))}
  Social     : {platforms_str}

  {Fore.RED + Style.BRIGHT}🔴 Merah  = CRITICAL / HIGH (aksi diperlukan){Style.RESET_ALL}
  {Fore.YELLOW}🟡 Kuning = MEDIUM{Style.RESET_ALL}
  {Fore.GREEN}🟢 Hijau  = Bersih / LOW / INFO{Style.RESET_ALL}
{Fore.YELLOW}  ⚡ Findings muncul LANGSUNG saat ditemukan ↓{Style.RESET_ALL}
{'─'*64}
""")

    global_seen  = set()
    all_findings = []
    per_sub      = []
    skipped      = []
    completed    = list(completed_prev)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(scan_one, url, args.depth,
                        scope_domains, global_seen, all_findings): url
            for url in targets
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                scanned_url, ec, fc, elapsed = future.result()
            except Exception as e:
                err(f"Error saat scan {url}: {e}")
                continue

            with _findings_lock:
                sub_findings = [f for f in all_findings
                                if f["source_subdomain"] == scanned_url]

            print_progress(scanned_url, elapsed, ec, fc, sub_findings)

            if ec == 0:
                diag = diagnose_subdomain(scanned_url, requests.Session())
                label = {
                    SKIP_LOGIN:    f"{Fore.YELLOW}auth/login wall{Style.RESET_ALL}",
                    SKIP_NOHTML:   f"{Fore.WHITE}non-HTML{Style.RESET_ALL}",
                    SKIP_TIMEOUT:  f"{Fore.RED}timeout/error{Style.RESET_ALL}",
                    SKIP_REDIRECT: f"{Fore.WHITE}redirect OOS{Style.RESET_ALL}",
                    SKIP_EMPTY:    f"{Fore.WHITE}SPA/JS-rendered{Style.RESET_ALL}",
                    None:          f"{Fore.GREEN}OK, 0 ext link{Style.RESET_ALL}",
                }.get(diag.get("skip_reason"), "unknown")
                with _print_lock:
                    print(f"      ↳ {label}: {diag.get('detail','')}")
                skipped.append(diag)

            completed.append(scanned_url)
            per_sub.append({"subdomain": scanned_url, "external_links": ec,
                             "findings": fc, "elapsed_sec": round(elapsed, 2)})

            if args.resume and len(completed) % 10 == 0:
                save_resume_state(args.resume, completed, all_findings)

    # ── Summary ───────────────────────────────────────────────────────────────
    with _findings_lock:
        final = list(all_findings)

    crit_n = sum(1 for f in final if f["severity"] == "CRITICAL")
    high_n = sum(1 for f in final if f["severity"] == "HIGH")
    med_n  = sum(1 for f in final if f["severity"] == "MEDIUM")
    low_n  = sum(1 for f in final if f["severity"] == "LOW")
    info_n = sum(1 for f in final if f["severity"] == "INFO")

    social  = [f for f in final if f.get("type") == "social_media"]
    broken  = [f for f in final if f.get("type") == "broken_link"]

    platform_counts = {}
    for f in social:
        p = f.get("platform","Unknown")
        platform_counts[p] = platform_counts.get(p, 0) + 1

    takeover_counts = {}
    for f in broken:
        t = f.get("takeover_type") or "none"
        takeover_counts[t] = takeover_counts.get(t, 0) + 1

    skip_counts = {}
    for s in skipped:
        k = s.get("skip_reason") or "accessible_no_ext"
        skip_counts[k] = skip_counts.get(k, 0) + 1

    report = {
        "scan_info": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "targets": targets, "scope": list(scope_domains),
            "depth": args.depth, "threads": args.threads, "version": VERSION,
        },
        "summary": {
            "total_subdomains":      len(targets),
            "total_findings":        len(final),
            "social_media_findings": len(social),
            "broken_link_findings":  len(broken),
            "critical": crit_n, "high": high_n, "medium": med_n,
            "low": low_n, "info": info_n,
            "by_platform": platform_counts,
            "by_takeover": takeover_counts,
            "skipped_breakdown": skip_counts,
        },
        "per_subdomain":      per_sub,
        "skipped_subdomains": skipped,
        "findings": sorted(final, key=lambda x: (
            0 if x.get("type") == "social_media" else 1,
            SEV_RANK.get(x["severity"], 9)
        )),
    }

    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2)

    if args.html_output:
        generate_html_report(report, args.html_output)
        ok(f"HTML report: {args.html_output}")

    if args.resume:
        save_resume_state(args.resume, completed, final)

    plat_str = "  ".join(f"{p}:{c}" for p, c in platform_counts.items()) or "-"
    tov_str  = "  ".join(f"{t.replace('_',' ')}:{c}"
                         for t, c in takeover_counts.items()
                         if t not in ("none",) and c > 0) or "-"

    print(f"""
{Fore.CYAN}{'═'*64}
  SCAN SELESAI – FINAL SUMMARY  (v{VERSION})
{'═'*64}{Style.RESET_ALL}
  Subdomain di-scan   : {len(targets)}
  Total findings      : {len(final)}

  {Fore.MAGENTA}Social Media        : {len(social)}{Style.RESET_ALL}  {plat_str}
  Broken/Takeover     : {len(broken)}  {tov_str}

  {Fore.RED + Style.BRIGHT}CRITICAL  : {crit_n}  ← ghost domain / orphaned NS{Style.RESET_ALL}
  {Fore.RED}HIGH      : {high_n}{Style.RESET_ALL}
  {Fore.YELLOW}MEDIUM    : {med_n}{Style.RESET_ALL}
  {Fore.GREEN}LOW       : {low_n}{Style.RESET_ALL}
  {Fore.CYAN}INFO      : {info_n}{Style.RESET_ALL}

  Skip breakdown:
    login wall        : {skip_counts.get(SKIP_LOGIN, 0)}
    non-HTML/API      : {skip_counts.get(SKIP_NOHTML, 0)}
    timeout/error     : {skip_counts.get(SKIP_TIMEOUT, 0)}
    redirect OOS      : {skip_counts.get(SKIP_REDIRECT, 0)}
    SPA/JS-rendered   : {skip_counts.get(SKIP_EMPTY, 0)}

  Report JSON  : {args.output}
  Report HTML  : {args.html_output or '–'}
{Fore.CYAN}{'═'*64}{Style.RESET_ALL}
""")

    if crit_n:
        err(f"☠  {crit_n} CRITICAL (orphaned NS)! Screenshot DNS + WHOIS, report segera!")
    if high_n:
        ok(f"{high_n} HIGH finding! Verifikasi WHOIS sebelum submit.")
    if social:
        ok(f"{len(social)} akun sosmed mati! Cek manual → HackerOne.")
    if info_n:
        info(f"{info_n} INFO (HTTP 403) – verifikasi manual.")
    if skip_counts.get(SKIP_EMPTY, 0):
        info(f"Tip: {skip_counts[SKIP_EMPTY]} subdomain SPA – coba katana.")


if __name__ == "__main__":
    main()
