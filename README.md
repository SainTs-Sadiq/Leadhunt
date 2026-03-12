# LeadHunt — OSINT Deep Lead Intelligence

A full-stack web app for sector-targeted B2B lead generation using OSINT techniques.

## Features
- 🔍 **Google Dorking** — smart search queries to surface company websites
- 🔗 **LinkedIn Scraping** — public company profile discovery
- 📧 **Email Discovery** — scrapes contact/about pages + WHOIS email extraction
- 🌐 **Social Profile Detection** — finds LinkedIn, Twitter, GitHub, Facebook, Instagram
- 🔎 **WHOIS Enrichment** — registrar, country, creation date
- 📊 **Lead Scoring** — ranks leads 0–100 by data completeness
- 💾 **CSV Export** — one-click export of all enriched leads

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the backend
```bash
python app.py
```
Backend runs at: http://localhost:5000

### 3. Open the dashboard
Open `index.html` in your browser OR visit http://localhost:5000

## Usage
1. Enter a **sector** (e.g. "fintech Nigeria", "SaaS HR tools", "cybersecurity startup")
2. Optionally add a **region** to narrow results
3. Set **scan depth** (5–30 leads)
4. Click **Initiate Scan** and watch leads populate live
5. Click any row to see full lead details
6. Export to CSV when done

## OSINT Sources Used
| Source | What it finds |
|--------|--------------|
| Google Dorking | Company domains, contact pages |
| DuckDuckGo HTML | Fallback search results |
| LinkedIn Public | Company names, profile URLs |
| Website Scraping | Email addresses from contact/about pages |
| WHOIS Lookup | Registrant emails, country, creation date |
| DNS MX Check | Email domain verification |
| Social Head Checks | Twitter, LinkedIn, GitHub, Facebook presence |

## Legal & Ethical Notes
- Only uses **publicly available** data sources
- Respects robots.txt via rate limiting and delays
- Intended for legitimate B2B lead research only
- Always comply with local data protection laws (GDPR, NDPA, etc.)

## Extending
- Add **Hunter.io API key** in `app.py` → `HUNTER_API_KEY` for professional email finding
- Add **Proxycurl** for richer LinkedIn data
- Plug in **Clearbit** for company enrichment
