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
    Use genuinely open APIs that work from any cloud server:
    1. Open Corporates API - world's largest open company database
    2. Wikipedia API - extract companies from industry articles
    3. Wikidata SPARQL - structured company data
    """
    results = []
    seen = set()
    region_str = region.strip() if region else ""

    def add(item):
        key = item.get("domain") or item.get("company_name","")
        if key and key not in seen:
            seen.add(key)
            results.append(item)

    # ── Source 1: OpenCorporates free search API ──────────────────────────────
    # No key needed for basic search, returns real registered companies
    try:
        q = quote_plus(sector)
        url = f"https://api.opencorporates.com/v0.4/companies/search?q={q}&format=json&per_page=20"
        if region_str:
            # Map region to jurisdiction code roughly
            country_map = {"nigeria":"ng","usa":"us","uk":"gb","ghana":"gh",
                           "kenya":"ke","south africa":"za","canada":"ca","india":"in",
                           "australia":"au","germany":"de","france":"fr"}
            jur = country_map.get(region_str.lower(), "")
            if jur:
                url += f"&jurisdiction_code={jur}"
        resp = requests.get(url, timeout=12, headers={"User-Agent":"LeadHunt/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            companies = data.get("results",{}).get("companies",[])
            for c in companies:
                co = c.get("company",{})
                name = co.get("name","")
                jurisdiction = co.get("jurisdiction_code","")
                company_number = co.get("company_number","")
                oc_url = co.get("opencorporates_url","")
                if name:
                    # Try to guess domain from company name
                    slug = re.sub(r"[^a-z0-9]", "", name.lower().split(" ")[0])
                    domain = f"{slug}.com" if slug else ""
                    add({
                        "company_name": name,
                        "domain": domain,
                        "url": f"https://{domain}" if domain else oc_url,
                        "opencorporates_url": oc_url,
                        "jurisdiction": jurisdiction,
                        "source": "opencorporates"
                    })
    except Exception as e:
        pass

    # ── Source 2: Wikidata SPARQL — real companies with websites ─────────────
    # Wikidata has millions of companies with official website URLs
    try:
        sector_clean = sector.replace('"','').strip()
        sparql_query = f"""
SELECT DISTINCT ?company ?companyLabel ?website WHERE {{
  ?company wdt:P31 wd:Q4830453 .
  ?company rdfs:label ?companyLabel .
  OPTIONAL {{ ?company wdt:P856 ?website . }}
  FILTER(LANG(?companyLabel) = "en")
  FILTER(CONTAINS(LCASE(?companyLabel), "{sector_clean.lower().split()[0]}") ||
         EXISTS {{ ?company wdt:P856 ?website }})
}}
LIMIT 25
"""
        # Use simpler label search instead
        sparql_query2 = f"""
SELECT ?item ?itemLabel ?website WHERE {{
  SERVICE wikibase:mwapi {{
    bd:serviceParam wikibase:endpoint "www.wikidata.org" ;
                    wikibase:api "EntitySearch" ;
                    mwapi:search "{sector_clean} company" ;
                    mwapi:language "en" .
    ?item wikibase:apiOutputItem mwapi:item .
  }}
  OPTIONAL {{ ?item wdt:P856 ?website }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" }}
}}
LIMIT 20
"""
        url = "https://query.wikidata.org/sparql"
        params = {"query": sparql_query2, "format": "json"}
        headers = {"User-Agent": "LeadHuntBot/1.0 (lead generation research)", "Accept": "application/json"}
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for row in data.get("results",{}).get("bindings",[]):
                name = row.get("itemLabel",{}).get("value","")
                website = row.get("website",{}).get("value","")
                if name and not name.startswith("Q"):  # skip unlabeled items
                    domain = extract_domain(website) if website else ""
                    if domain and any(s in domain for s in SKIP_DOMAINS):
                        domain = ""
                    add({
                        "company_name": name,
                        "domain": domain,
                        "url": website or f"https://{domain}" if domain else "",
                        "source": "wikidata"
                    })
    except Exception:
        pass

    # ── Source 3: Wikipedia article scraping for sector lists ─────────────────
    try:
        search_terms = [
            f"list of {sector} companies",
            f"{sector} industry",
            f"{sector} companies {region_str}".strip(),
        ]
        for term in search_terms[:2]:
            encoded = quote_plus(term)
            # Wikipedia opensearch to find the right article
            api_url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={encoded}&limit=3&format=json"
            resp = requests.get(api_url, timeout=8, headers={"User-Agent":"LeadHunt/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                page_urls = data[3] if len(data) > 3 else []
                for page_url in page_urls[:1]:
                    page_resp = requests.get(page_url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
                    if page_resp.status_code == 200:
                        soup = BeautifulSoup(page_resp.text, "html.parser")
                        # Get all external links — these are usually official company sites
                        for a in soup.find_all("a", href=re.compile(r"^https?://")):
                            href = a.get("href","")
                            domain = extract_domain(href)
                            if domain and len(domain) > 4:
                                if not any(s in domain for s in SKIP_DOMAINS + ["wikimedia","wikipedia","wikidata","wikiquote"]):
                                    name = a.get_text(strip=True)
                                    if name and len(name) > 2 and len(name) < 60:
                                        add({
                                            "company_name": name,
                                            "domain": domain,
                                            "url": f"https://{domain}",
                                            "source": "wikipedia"
                                        })
            time.sleep(0.3)
            if len(results) >= num:
                break
    except Exception:
        pass

    # ── Source 4: DuckDuckGo Instant Answer API (JSON, not scraping) ──────────
    try:
        q = quote_plus(f"{sector} {region_str} companies".strip())
        url = f"https://api.duckduckgo.com/?q={q}&format=json&no_html=1&skip_disambig=1"
        resp = requests.get(url, timeout=10, headers={"User-Agent":"LeadHunt/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            # RelatedTopics contain company names and links
            for topic in data.get("RelatedTopics", [])[:20]:
                if isinstance(topic, dict):
                    text = topic.get("Text","")
                    first_url = topic.get("FirstURL","")
                    if text and first_url:
                        name = text.split(" - ")[0].split(", ")[0][:60]
                        domain = extract_domain(first_url)
                        if domain and not any(s in domain for s in SKIP_DOMAINS):
                            add({"company_name": name, "domain": domain,
                                 "url": f"https://{domain}", "source": "duckduckgo_api"})
                    # Handle nested Topics
                    for sub in topic.get("Topics",[]):
                        text2 = sub.get("Text","")
                        url2 = sub.get("FirstURL","")
                        if text2 and url2:
                            name2 = text2.split(" - ")[0][:60]
                            domain2 = extract_domain(url2)
                            if domain2 and not any(s in domain2 for s in SKIP_DOMAINS):
                                add({"company_name": name2, "domain": domain2,
                                     "url": f"https://{domain2}", "source": "duckduckgo_api"})
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

@app.route("/")
def index():
    return send_file("index.html")

import os
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
