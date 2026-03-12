from flask import Flask, jsonify, request, render_template_string, send_file
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import re
import time
import json
import csv
import io
import random
from urllib.parse import urljoin, urlparse, quote_plus
from datetime import datetime
import threading
import uuid

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# In-memory job store
jobs = {}

# ── OSINT Utilities ──────────────────────────────────────────────────────────

HEADERS_POOL = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36"},
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"},
]

def get_headers():
    return random.choice(HEADERS_POOL)

def safe_get(url, timeout=10):
    try:
        r = requests.get(url, headers=get_headers(), timeout=timeout)
        r.raise_for_status()
        return r
    except Exception:
        return None

# ── DuckDuckGo Search (cloud-friendly) ───────────────────────────────────────

def search_duckduckgo(query, num_results=15):
    """Use DuckDuckGo HTML search - works from cloud servers."""
    found_domains = set()
    results = []
    encoded = quote_plus(query)
    
    # DuckDuckGo HTML endpoint - no JS required, no rate limiting like Google
    url = f"https://html.duckduckgo.com/html/?q={encoded}"
    headers = {
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ]),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://duckduckgo.com/",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            # DDG HTML result links
            for a in soup.find_all("a", class_="result__url"):
                href = a.get_text(strip=True)
                if href and not href.startswith("http"):
                    href = "https://" + href
                parsed = urlparse(href)
                domain = parsed.netloc.replace("www.", "")
                if domain and domain not in found_domains and len(domain) > 4:
                    # Filter out junk domains
                    skip = ["duckduckgo", "google", "facebook", "youtube", "twitter",
                            "wikipedia", "amazon", "reddit", "yelp", "indeed"]
                    if not any(s in domain for s in skip):
                        found_domains.add(domain)
                        title_el = a.find_previous("a", class_="result__a")
                        company_name = title_el.get_text(strip=True) if title_el else domain.split(".")[0].title()
                        results.append({
                            "domain": domain,
                            "company_name": company_name,
                            "url": href,
                            "source": "duckduckgo"
                        })
            # Also grab result__a links directly
            for a in soup.find_all("a", class_="result__a"):
                href = a.get("href", "")
                # DDG redirects through /l/?uddg=
                if "uddg=" in href:
                    try:
                        from urllib.parse import unquote
                        href = unquote(href.split("uddg=")[1].split("&")[0])
                    except Exception:
                        pass
                parsed = urlparse(href)
                domain = parsed.netloc.replace("www.", "")
                if domain and domain not in found_domains and len(domain) > 4:
                    skip = ["duckduckgo", "google", "facebook", "youtube", "twitter",
                            "wikipedia", "amazon", "reddit", "yelp", "indeed"]
                    if not any(s in domain for s in skip):
                        found_domains.add(domain)
                        results.append({
                            "domain": domain,
                            "company_name": a.get_text(strip=True) or domain.split(".")[0].title(),
                            "url": href,
                            "source": "duckduckgo"
                        })
    except Exception as e:
        pass
    time.sleep(random.uniform(1.0, 2.0))
    return results[:num_results]

def google_dork_companies(sector, region="", num_results=20):
    """Multi-source company discovery using DuckDuckGo + public directories."""
    results = []
    seen = set()

    region_str = f" {region}" if region else ""

    queries = [
        f"{sector}{region_str} company contact email",
        f"{sector}{region_str} startup website",
        f"{sector}{region_str} business directory",
        f"{sector}{region_str} companies list",
    ]

    for query in queries:
        hits = search_duckduckgo(query, num_results=10)
        for h in hits:
            key = h.get("domain", "")
            if key and key not in seen:
                seen.add(key)
                results.append(h)
        if len(results) >= num_results:
            break
        time.sleep(random.uniform(0.8, 1.5))

    return results[:num_results]

# ── LinkedIn Public Scraping ─────────────────────────────────────────────────

def scrape_linkedin_companies(sector, num=10):
    """Find companies via DuckDuckGo LinkedIn search (avoids LinkedIn blocks)."""
    results = []
    query = f"site:linkedin.com/company {sector}"
    hits = search_duckduckgo(query, num_results=num)
    for h in hits:
        domain = h.get("domain", "")
        url = h.get("url", "")
        name = h.get("company_name", "")
        if "linkedin.com" in domain or "linkedin.com" in url:
            slug_match = re.search(r"linkedin\.com/company/([^/?]+)", url)
            slug = slug_match.group(1) if slug_match else ""
            results.append({
                "company_name": name,
                "linkedin_url": f"https://linkedin.com/company/{slug}" if slug else url,
                "source": "linkedin_ddg"
            })
        else:
            # Non-linkedin result — still useful as a company lead
            if name and domain:
                results.append({
                    "company_name": name,
                    "domain": domain,
                    "source": "linkedin_ddg"
                })
    return results[:num]

# ── Whois Enrichment ─────────────────────────────────────────────────────────

def whois_lookup(domain):
    """Get registrant info from WHOIS."""
    data = {}
    try:
        w = whois.whois(domain)
        data["registrar"] = getattr(w, "registrar", None)
        data["creation_date"] = str(getattr(w, "creation_date", None))
        data["country"] = getattr(w, "country", None)
        emails = getattr(w, "emails", None)
        if emails:
            if isinstance(emails, list):
                data["whois_emails"] = [e for e in emails if e]
            else:
                data["whois_emails"] = [emails]
    except Exception:
        pass
    return data

# ── Email Discovery ──────────────────────────────────────────────────────────

EMAIL_PATTERNS = [
    "{first}@{domain}",
    "{first}.{last}@{domain}",
    "{f}{last}@{domain}",
    "info@{domain}",
    "contact@{domain}",
    "hello@{domain}",
    "sales@{domain}",
]

def verify_email_mx(email):
    """Check if the domain has valid MX records (basic verification)."""
    domain = email.split("@")[-1]
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        return False

def scrape_emails_from_website(url):
    """Scrape emails from contact/about pages."""
    found = set()
    pages = [url, urljoin(url, "/contact"), urljoin(url, "/about"), urljoin(url, "/contact-us")]
    
    for page in pages:
        resp = safe_get(page, timeout=8)
        if resp:
            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", resp.text)
            for e in emails:
                if not any(x in e.lower() for x in ["example", "placeholder", "yourname", "noreply"]):
                    found.add(e.lower())
        time.sleep(0.5)
    
    return list(found)

# ── Social Media Discovery ───────────────────────────────────────────────────

def find_social_profiles(domain, company_name):
    """Find social media profiles for a company."""
    socials = {}
    slug = re.sub(r"[^a-z0-9]", "", company_name.lower())[:20] if company_name else ""
    clean_domain = domain.replace(".com","").replace(".io","").replace(".co","")
    
    # Check common social URLs via HTTP HEAD
    checks = {
        "twitter": [f"https://twitter.com/{slug}", f"https://twitter.com/{clean_domain}"],
        "linkedin": [f"https://linkedin.com/company/{slug}", f"https://linkedin.com/company/{clean_domain}"],
        "github": [f"https://github.com/{slug}", f"https://github.com/{clean_domain}"],
        "facebook": [f"https://facebook.com/{slug}"],
    }
    
    for platform, urls in checks.items():
        for u in urls:
            try:
                r = requests.head(u, headers=get_headers(), timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    socials[platform] = u
                    break
            except Exception:
                pass
        time.sleep(0.3)
    
    # Also parse website for social links
    resp = safe_get(f"https://{domain}")
    if resp:
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            for platform, pattern in [
                ("twitter", "twitter.com"), ("linkedin", "linkedin.com/company"),
                ("github", "github.com"), ("facebook", "facebook.com"),
                ("instagram", "instagram.com"), ("youtube", "youtube.com")
            ]:
                if platform not in socials and pattern in href:
                    socials[platform] = href
    
    return socials

# ── Main Lead Builder ────────────────────────────────────────────────────────

def build_lead(raw, sector):
    domain = raw.get("domain", "")
    company_name = raw.get("company_name", "")
    
    if not domain and not company_name:
        return None
    
    # Guess domain from company name
    if not domain and company_name:
        slug = re.sub(r"[^a-z0-9]", "", company_name.lower())
        domain = f"{slug}.com"
    
    lead = {
        "id": str(uuid.uuid4())[:8],
        "company_name": company_name or domain.split(".")[0].title(),
        "domain": domain,
        "website": f"https://{domain}" if domain else "",
        "sector": sector,
        "emails": [],
        "social_profiles": {},
        "whois": {},
        "score": 0,
        "sources": [raw.get("source", "unknown")],
        "discovered_at": datetime.utcnow().isoformat(),
    }
    
    if domain:
        # Scrape emails
        emails = scrape_emails_from_website(f"https://{domain}")
        lead["emails"] = emails[:5]
        
        # WHOIS
        lead["whois"] = whois_lookup(domain)
        if lead["whois"].get("whois_emails"):
            for e in lead["whois"]["whois_emails"]:
                if e not in lead["emails"]:
                    lead["emails"].append(e)
        
        # Social profiles
        lead["social_profiles"] = find_social_profiles(domain, lead["company_name"])
    
    # Score the lead
    score = 0
    if lead["emails"]: score += 40
    if lead["social_profiles"].get("linkedin"): score += 20
    if lead["social_profiles"].get("twitter"): score += 10
    if lead["website"]: score += 15
    if lead["whois"].get("country"): score += 5
    if len(lead["social_profiles"]) >= 2: score += 10
    lead["score"] = min(score, 100)
    
    return lead

# ── Background Job Runner ────────────────────────────────────────────────────

def run_scan_job(job_id, sector, region, depth):
    jobs[job_id]["status"] = "running"
    jobs[job_id]["progress"] = 5
    jobs[job_id]["log"] = [f"Starting scan for sector: {sector}"]
    
    all_raw = []
    
    # Step 1: Google Dorking
    jobs[job_id]["log"].append("🔍 Running Google dorking queries...")
    jobs[job_id]["progress"] = 15
    google_results = google_dork_companies(sector, region, num_results=depth * 3)
    all_raw.extend(google_results)
    jobs[job_id]["log"].append(f"   Found {len(google_results)} domains via Google")
    
    # Step 2: LinkedIn
    jobs[job_id]["progress"] = 35
    jobs[job_id]["log"].append("🔗 Scanning LinkedIn public profiles...")
    linkedin_results = scrape_linkedin_companies(sector, num=depth * 2)
    all_raw.extend(linkedin_results)
    jobs[job_id]["log"].append(f"   Found {len(linkedin_results)} companies via LinkedIn")
    
    # Step 3: Deduplicate
    jobs[job_id]["progress"] = 50
    jobs[job_id]["log"].append("🧹 Deduplicating results...")
    seen = set()
    deduped = []
    for r in all_raw:
        key = r.get("domain") or r.get("company_name", "")
        if key and key not in seen:
            seen.add(key)
            deduped.append(r)
    jobs[job_id]["log"].append(f"   {len(deduped)} unique targets after dedup")
    
    # Step 4: Enrich leads
    leads = []
    total = min(len(deduped), depth)
    for i, raw in enumerate(deduped[:total]):
        pct = 50 + int((i / total) * 45)
        jobs[job_id]["progress"] = pct
        jobs[job_id]["log"].append(f"⚙️  Enriching lead {i+1}/{total}: {raw.get('domain') or raw.get('company_name', '')}...")
        lead = build_lead(raw, sector)
        if lead:
            leads.append(lead)
            jobs[job_id]["leads"] = leads  # live update
        time.sleep(random.uniform(0.5, 1.2))
    
    # Sort by score
    leads.sort(key=lambda x: x["score"], reverse=True)
    
    jobs[job_id]["status"] = "done"
    jobs[job_id]["progress"] = 100
    jobs[job_id]["leads"] = leads
    jobs[job_id]["log"].append(f"✅ Scan complete. {len(leads)} leads found.")
    jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()

# ── API Routes ───────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json
    sector = data.get("sector", "").strip()
    region = data.get("region", "").strip()
    depth = max(5, min(int(data.get("depth", 10)), 30))
    
    if not sector:
        return jsonify({"error": "sector is required"}), 400
    
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "id": job_id,
        "sector": sector,
        "region": region,
        "depth": depth,
        "status": "queued",
        "progress": 0,
        "leads": [],
        "log": [],
        "created_at": datetime.utcnow().isoformat(),
    }
    
    t = threading.Thread(target=run_scan_job, args=(job_id, sector, region, depth), daemon=True)
    t.start()
    
    return jsonify({"job_id": job_id})

@app.route("/api/job/<job_id>", methods=["GET"])
def get_job(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@app.route("/api/job/<job_id>/export", methods=["GET"])
def export_csv(job_id):
    job = jobs.get(job_id)
    if not job or not job.get("leads"):
        return jsonify({"error": "No leads"}), 404
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Company", "Domain", "Website", "Sector", "Emails", "LinkedIn", "Twitter", "GitHub", "Score", "Country", "Discovered"])
    
    for lead in job["leads"]:
        writer.writerow([
            lead.get("company_name", ""),
            lead.get("domain", ""),
            lead.get("website", ""),
            lead.get("sector", ""),
            "; ".join(lead.get("emails", [])),
            lead.get("social_profiles", {}).get("linkedin", ""),
            lead.get("social_profiles", {}).get("twitter", ""),
            lead.get("social_profiles", {}).get("github", ""),
            lead.get("score", 0),
            lead.get("whois", {}).get("country", ""),
            lead.get("discovered_at", ""),
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"leads_{job['sector'].replace(' ','_')}_{job_id[:6]}.csv"
    )

@app.route("/")
def index():
    return send_file("index.html")

import os
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
