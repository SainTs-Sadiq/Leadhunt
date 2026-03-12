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

SKIP_DOMAINS = [
    "duckduckgo", "google", "facebook", "youtube", "twitter",
    "wikipedia", "amazon", "reddit", "yelp", "indeed", "glassdoor",
    "crunchbase", "bloomberg", "forbes", "techcrunch", "github",
    "stackoverflow", "quora", "medium", "substack", "angellist"
]

def extract_domain(url):
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        return parsed.netloc.replace("www.", "").strip()
    except Exception:
        return ""

# ── Free Public APIs (no scraping needed) ────────────────────────────────────

def search_companies_via_apis(sector, region="", num=20):
    """
    Multi-source company discovery using free public APIs.
    Sources: Wikidata SPARQL, Wikipedia category members, DDG Instant Answer
    """
    results = []
    seen = set()
    region_str = region.strip() if region else ""

    def add(item):
        # Only add items that have at least a company name
        name = item.get("company_name","").strip()
        domain = item.get("domain","").strip()
        # Skip stock exchanges, indices, junk domains
        junk = ["nyse","nasdaq","exchange","index","inc.com","nseindia",
                "six-group","bourse","euronext","sec.gov","investor"]
        if any(j in (domain+name).lower() for j in junk):
            return
        key = domain or name
        if key and key not in seen and len(name) > 2:
            seen.add(key)
            results.append(item)

    # ── Source 1: Wikidata SPARQL with official website URLs ─────────────────
    # This is the most reliable — gets companies WITH their actual websites
    try:
        sector_word = sector.strip().split()[0].lower()
        sparql = f"""
SELECT DISTINCT ?companyLabel ?website ?countryLabel WHERE {{
  ?company wdt:P31/wdt:P279* wd:Q4830453 .
  ?company wdt:P856 ?website .
  ?company rdfs:label ?companyLabel .
  OPTIONAL {{ ?company wdt:P17 ?country .
    ?country rdfs:label ?countryLabel FILTER(LANG(?countryLabel)="en") }}
  FILTER(LANG(?companyLabel) = "en")
  FILTER(CONTAINS(LCASE(STR(?website)), "{sector_word}") ||
         CONTAINS(LCASE(?companyLabel), "{sector_word}"))
}}
LIMIT 30
"""
        url = "https://query.wikidata.org/sparql"
        params = {"query": sparql, "format": "json"}
        headers = {"User-Agent": "LeadHuntBot/1.0", "Accept": "application/json"}
        resp = requests.get(url, params=params, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for row in data.get("results",{}).get("bindings",[]):
                name = row.get("companyLabel",{}).get("value","")
                website = row.get("website",{}).get("value","")
                country = row.get("countryLabel",{}).get("value","")
                if name and not name.startswith("Q") and website:
                    domain = extract_domain(website)
                    if domain and not any(s in domain for s in SKIP_DOMAINS):
                        add({
                            "company_name": name,
                            "domain": domain,
                            "url": website,
                            "country": country,
                            "source": "wikidata"
                        })
    except Exception:
        pass

    # ── Source 2: Wikidata — broader search by industry keyword ──────────────
    if len(results) < 10:
        try:
            sector_q = quote_plus(sector)
            # Use Wikidata entity search to find companies matching sector
            url = f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={sector_q}+company&language=en&type=item&limit=20&format=json"
            resp = requests.get(url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("search",[]):
                    name = item.get("label","")
                    desc = item.get("description","")
                    qid = item.get("id","")
                    # Only keep items described as companies
                    if any(w in desc.lower() for w in ["company","corporation","startup","firm","inc","ltd","business"]):
                        # Fetch website for this entity
                        try:
                            detail_url = f"https://www.wikidata.org/w/api.php?action=wbgetclaims&entity={qid}&property=P856&format=json"
                            detail_resp = requests.get(detail_url, timeout=8, headers={"User-Agent":"LeadHunt/1.0"})
                            website = ""
                            if detail_resp.status_code == 200:
                                claims = detail_resp.json().get("claims",{}).get("P856",[])
                                if claims:
                                    website = claims[0].get("mainsnak",{}).get("datavalue",{}).get("value","")
                            domain = extract_domain(website) if website else re.sub(r"[^a-z0-9]","",name.lower().split()[0]) + ".com"
                            if not any(s in domain for s in SKIP_DOMAINS):
                                add({
                                    "company_name": name,
                                    "domain": domain,
                                    "url": website or f"https://{domain}",
                                    "description": desc,
                                    "source": "wikidata_search"
                                })
                        except Exception:
                            add({
                                "company_name": name,
                                "domain": re.sub(r"[^a-z0-9]","",name.lower().split()[0]) + ".com",
                                "url": "",
                                "description": desc,
                                "source": "wikidata_search"
                            })
                        time.sleep(0.1)
        except Exception:
            pass

    # ── Source 3: Wikipedia category members API ──────────────────────────────
    # Gets all articles in a Wikipedia category e.g. "Fintech companies"
    if len(results) < 15:
        try:
            categories = [
                f"{sector} companies",
                f"{sector} software companies",
                f"{sector} startups",
            ]
            if region_str:
                categories.insert(0, f"{sector} companies of {region_str}")

            for cat in categories[:2]:
                cat_encoded = quote_plus(cat.title())
                url = f"https://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:{cat_encoded}&cmlimit=30&format=json"
                resp = requests.get(url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    members = data.get("query",{}).get("categorymembers",[])
                    for m in members:
                        title = m.get("title","")
                        if title and not title.startswith("Category:") and not title.startswith("List of"):
                            # Get the Wikipedia page and find official website
                            page_q = quote_plus(title)
                            page_url = f"https://en.wikipedia.org/w/api.php?action=query&titles={page_q}&prop=extlinks&ellimit=10&format=json"
                            try:
                                page_resp = requests.get(page_url, timeout=8, headers={"User-Agent":"LeadHunt/1.0"})
                                if page_resp.status_code == 200:
                                    pages = page_resp.json().get("query",{}).get("pages",{})
                                    website = ""
                                    for p in pages.values():
                                        for link in p.get("extlinks",[]):
                                            href = link.get("*","") or link.get("url","")
                                            d = extract_domain(href)
                                            if d and not any(s in d for s in SKIP_DOMAINS + ["wikimedia","archive.org","sec.gov"]):
                                                website = href
                                                break
                                    domain = extract_domain(website) if website else re.sub(r"[^a-z0-9]","",title.lower().split()[0]) + ".com"
                                    add({
                                        "company_name": title,
                                        "domain": domain,
                                        "url": website or f"https://{domain}",
                                        "source": "wikipedia_category"
                                    })
                            except Exception:
                                add({
                                    "company_name": title,
                                    "domain": re.sub(r"[^a-z0-9]","",title.lower().split()[0]) + ".com",
                                    "url": "",
                                    "source": "wikipedia_category"
                                })
                            time.sleep(0.15)
                        if len(results) >= num:
                            break
                if len(results) >= num:
                    break
        except Exception:
            pass

    # ── Source 4: DDG Instant Answer for company lists ────────────────────────
    if len(results) < 10:
        try:
            for q_suffix in [f"{sector} companies", f"top {sector} startups", f"best {sector} software"]:
                q = quote_plus(f"{q_suffix} {region_str}".strip())
                url = f"https://api.duckduckgo.com/?q={q}&format=json&no_html=1&skip_disambig=1"
                resp = requests.get(url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for topic in data.get("RelatedTopics",[]):
                        if isinstance(topic, dict):
                            subtopics = topic.get("Topics", [topic])
                            for sub in subtopics:
                                text = sub.get("Text","")
                                first_url = sub.get("FirstURL","")
                                if text and first_url:
                                    name = text.split(" - ")[0].split(", ")[0].strip()[:60]
                                    domain = extract_domain(first_url)
                                    if domain and not any(s in domain for s in SKIP_DOMAINS):
                                        add({"company_name": name, "domain": domain,
                                             "url": f"https://{domain}", "source": "ddg_api"})
                time.sleep(0.5)
                if len(results) >= num:
                    break
        except Exception:
            pass

    return results[:num]

def google_dork_companies(sector, region="", num_results=20):
    return search_companies_via_apis(sector, region, num=num_results)

def scrape_linkedin_companies(sector, num=10):
    return []  # Handled inside search_companies_via_apis now

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

@app.route("/api/debug", methods=["GET"])
def debug_scan():
    """Test all data sources and return raw results."""
    sector = request.args.get("sector", "fintech")
    region = request.args.get("region", "")
    log = []

    # Test OpenCorporates
    try:
        q = quote_plus(sector)
        url = f"https://api.opencorporates.com/v0.4/companies/search?q={q}&format=json&per_page=5"
        resp = requests.get(url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
        log.append(f"OpenCorporates status: {resp.status_code}, length: {len(resp.text)}, preview: {resp.text[:200]}")
    except Exception as e:
        log.append(f"OpenCorporates ERROR: {str(e)}")

    # Test DuckDuckGo API
    try:
        q = quote_plus(f"{sector} companies")
        url = f"https://api.duckduckgo.com/?q={q}&format=json&no_html=1&skip_disambig=1"
        resp = requests.get(url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
        log.append(f"DDG API status: {resp.status_code}, length: {len(resp.text)}, preview: {resp.text[:200]}")
    except Exception as e:
        log.append(f"DDG API ERROR: {str(e)}")

    # Test Wikipedia API
    try:
        q = quote_plus(f"list of {sector} companies")
        url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={q}&limit=3&format=json"
        resp = requests.get(url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
        log.append(f"Wikipedia status: {resp.status_code}, length: {len(resp.text)}, preview: {resp.text[:200]}")
    except Exception as e:
        log.append(f"Wikipedia ERROR: {str(e)}")

    # Test Wikidata
    try:
        url = "https://query.wikidata.org/sparql"
        params = {"query": "SELECT ?item ?itemLabel WHERE { ?item wdt:P31 wd:Q4830453 . SERVICE wikibase:label { bd:serviceParam wikibase:language 'en' } } LIMIT 3", "format": "json"}
        resp = requests.get(url, params=params, timeout=10, headers={"User-Agent":"LeadHunt/1.0", "Accept":"application/json"})
        log.append(f"Wikidata status: {resp.status_code}, length: {len(resp.text)}, preview: {resp.text[:200]}")
    except Exception as e:
        log.append(f"Wikidata ERROR: {str(e)}")

    # Test full search function
    try:
        results = search_companies_via_apis(sector, region, num=5)
        log.append(f"search_companies_via_apis returned {len(results)} results")
        for r in results[:3]:
            log.append(f"  -> {r}")
    except Exception as e:
        log.append(f"search_companies_via_apis ERROR: {str(e)}")

    return jsonify({"log": log})

@app.route("/")
def index():
    return send_file("index.html")

import os
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
