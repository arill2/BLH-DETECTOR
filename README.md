# Broken Link Hijacking (BLH) Scanner v4.0

**Scanner canggih untuk menemukan Broken Link Hijacking, Subdomain Takeover, Ghost Domain (Orphaned NS), dan Social Media Account Takeover.**

Dirancang khusus untuk **bug bounty hunter** dan **security researcher** yang ingin menemukan kerentanan high-impact dengan cepat dan akurat.

![Version](https://img.shields.io/badge/version-4.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Fitur Utama (v4.0)

- **CRITICAL** → Deteksi **Ghost Domain / Orphaned NS** (semua NS REFUSED)
- **HIGH** → Dangling CNAME + Expired Domain
- **Social Media Takeover** (Twitter/X, Instagram, Facebook, YouTube, TikTok, GitHub, LinkedIn)
- DNS Resolver menggunakan **Public DNS** (tidak tergantung resolver lokal/VPN)
- DNS Cache + Resume scan (bisa dilanjutkan jika ter-interupsi)
- WHOIS lookup otomatis untuk HIGH/CRITICAL findings
- Progress bar berwarna berdasarkan severity
- HTML Report yang cantik & interaktif
- Multi-threading + retry logic
- Fingerprint 35+ cloud service untuk takeover

### Changelog Penting v4.0
- Deteksi Orphaned NS yang lebih akurat (kasus `6connex.us` dll)
- Public DNS fallback
- Warna progress bar sesuai severity
- WHOIS integration
- Resume capability

---

## 📋 Persyaratan

```bash
pip install requests beautifulsoup4 tldextract colorama dnspython python-whois

```bash
Scan dari file subdomain
python blh_scanner.py --file subdomains.txt

```bash
Scan single target
python blh_scanner.py --url https://target.com --depth 3

```bash
Full command (rekomendasi)
python blh_scanner.py \
  --file subdomains.txt \
  --depth 2 \
  --threads 5 \
  --whois \
  --html-output report.html

```bash
Resume scan (jika terputus)
python blh_scanner.py --file subdomains.txt --resume state.json
