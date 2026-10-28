# 🛡️ OfferShield AI — Forensic Scam Investigator

> An autonomous AI agent that forensically inspects job & internship offer communications for recruitment fraud — combining **deterministic network-forensics tools** (DNS, WHOIS, fuzzy brand matching) with **Gemini multimodal reasoning** and **live Google Search grounding**.

OfferShield AI takes a suspicious job offer (pasted text, an uploaded offer-letter **PDF**, or a **screenshot**) and produces a full forensic audit: risk scores, an explainable red-flag heatmap, extracted suspect payment/contact identifiers, ready-to-file **cybercrime complaint drafts**, a **college placement-cell memo**, and a downloadable **PDF audit report**.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [How It Works — Architecture](#-how-it-works--architecture)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the App](#-running-the-app)
- [Usage Guide](#-usage-guide)
- [The 4 Forensic Tools](#-the-4-forensic-tools)
- [Output Schema](#-output-schema)
- [Benchmark & Evaluation Suite](#-benchmark--evaluation-suite)
- [Detection Rules](#-detection-rules)
- [Export Formats](#-export-formats)
- [Troubleshooting](#-troubleshooting)
- [Project Notes](#-project-notes)

---

## ✨ Key Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Multimodal Input** | Paste text/emails, upload multi-page offer-letter **PDFs** (text-layer extraction via `pypdf`), or upload **screenshots/images** analyzed directly by Gemini's vision. |
| 2 | **Live Google Search Grounding** | The agent performs a real-time web search to verify company existence, official career portals, and reported scam complaints — with a knowledge-base fallback if search quota is throttled. |
| 3 | **Typosquatting / Impersonation Detection** | Fuzzy brand matching (`RapidFuzz`) against a canonical list of major employers (TCS, Infosys, Wipro, Google, Microsoft, …) plus trademark-embedding checks. |
| 4 | **WHOIS Domain Age Scanner** | Detects freshly registered "disposable" scam domains (< 180 days old). |
| 5 | **DNS MX Verification** | Confirms the recruiter's domain actually has mail servers, and flags generic free-mail (Gmail/Yahoo/Outlook) used for "corporate" hiring. |
| 6 | **Explainable Red-Flag Heatmap** | An HTML-highlighted view of the original offer text with each suspicious phrase color-coded by evidence category and severity. |
| 7 | **Structured Forensic Output** | A Pydantic-validated schema guarantees consistent, machine-readable results every run. |
| 8 | **Suspect Identifier Extraction** | Automatically pulls out UPI VPA handles, bank/payment links, phone numbers, unofficial emails, and Telegram channels. |
| 9 | **Legal Redressal Drafts** | Auto-generates a formal **cybercrime.gov.in** complaint (citing IT Act §66C/66D & BNS cheating provisions) and a **Training & Placement Cell** incident memo. |
| 10 | **Official PDF Audit Report** | One-click downloadable forensic report (`fpdf2`) with summary, risk decomposition, evidence, actions, and the safe reply draft. |
| 11 | **Observable Agent Trace** | A chronological, step-by-step log of every tool invocation and reasoning step the agent took (no black box). |
| 12 | **Benchmark Suite** | An 8-case evaluation harness with verified ground truth computing Accuracy, Precision, Recall, F1, a confusion matrix, and average latency. |

---

## 🧠 How It Works — Architecture

```
                       ┌──────────────────────────────────────────┐
   TEXT / PDF / IMAGE ─▶│           PAYLOAD INGESTION             │
                       │  • text area  • pypdf text extraction    │
                       │  • Pillow image for vision input         │
                       └────────────────┬─────────────────────────┘
                                        │
                                        ▼
                       ┌──────────────────────────────────────────┐
                       │      DETERMINISTIC FORENSIC TOOLS        │
                       │  (run before the LLM — real, non-fake    │
                       │   evidence injected into the prompt)     │
                       │                                          │
                       │  Tool 1: DNS MX Resolver         (dnspython) │
                       │  Tool 2: Levenshtein Typosquat   (RapidFuzz) │
                       │  Tool 3: WHOIS Domain Age        (python-whois) │
                       │  Tool 4: Google Search Grounding (Gemini) │
                       └────────────────┬─────────────────────────┘
                                        │
                                        ▼
                       ┌──────────────────────────────────────────┐
                       │   COGNITIVE AGENT SYNTHESIS              │
                       │   Model: gemini-3.5-flash-lite           │
                       │   • All tool findings injected as        │
                       │     "Investigation Evidence"             │
                       │   • Enforced detection rules             │
                       │   • response_schema = OfferAnalysis      │
                       │     (structured JSON output)             │
                       └────────────────┬─────────────────────────┘
                                        │
                                        ▼
                       ┌──────────────────────────────────────────┐
                       │              OUTPUTS                     │
                       │  • Risk scores (financial/identity/      │
                       │    process + overall verdict)            │
                       │  • Red-flag list & explainable heatmap   │
                       │  • Suspect payment/contact handles       │
                       │  • Safe reply draft                      │
                       │  • Cybercrime complaint + T&P memo       │
                       │  • Forensic PDF report                   │
                       │  • Full agent execution trace            │
                       └──────────────────────────────────────────┘
```

**Why tools-then-LLM?** Deterministic checks (DNS, WHOIS, fuzzy matching) produce *verifiable* evidence. That evidence is passed into Gemini as structured context, so the model reasons over real data instead of hallucinating — and the app displays exactly which tool produced which finding.

---

## 📁 Project Structure

```
offershield-ai/
│
├── app.py                 # Entire application (Streamlit UI + agent engine + tools)
├── .env                   # API key configuration (KEEP PRIVATE — do not commit)
├── README.md              # This documentation
├── pip_install.log        # Historical pip install output
├── venv/                  # Python 3.12 virtual environment with all dependencies
└── __pycache__/           # Bytecode cache (auto-generated)
```

> **Note:** The project is intentionally a **single-file application** — all deterministic tools, the Pydantic schema, the agent engine, the PDF builder, the benchmark suite, and the full UI live in `app.py`.

---

## 💻 Requirements

| Component | Version / Notes |
|-----------|-----------------|
| **Python** | 3.10+ (project runs on **3.12.10**) |
| **Gemini API Key** | Free tier works — get one at [Google AI Studio](https://aistudio.google.com/apikey) |
| **OS** | Windows / macOS / Linux |
| **Internet** | Required (Gemini API, Google Search grounding, DNS & WHOIS lookups) |

### Core Python Dependencies

| Package | Role |
|---------|------|
| `streamlit` | Web UI framework |
| `google-genai` | Gemini API client + Google Search grounding tool |
| `pydantic` | Structured output schema & validation |
| `python-dotenv` | Loads `.env` configuration |
| `pandas` | Benchmark results & data tables |
| `dnspython` | DNS MX record resolution |
| `python-whois` | WHOIS domain age lookup |
| `rapidfuzz` | Fuzzy string matching for typosquatting detection |
| `pypdf` | PDF text-layer extraction |
| `fpdf2` | Forensic PDF report generation |
| `Pillow` | Screenshot/image handling |

---

## ⚙️ Installation

### Option A — Use the existing virtual environment (recommended)

The repo already ships with a configured `venv\`:

```bash
# Windows (Command Prompt / PowerShell)
venv\Scripts\activate
```

```bash
# macOS / Linux
source venv/bin/activate
```

If packages are missing, reinstall them:

```bash
pip install streamlit pandas pydantic python-dotenv google-genai \
            Pillow fpdf2 rapidfuzz pypdf python-whois dnspython
```

### Option B — Fresh setup from scratch

```bash
# 1. Clone / open the project
cd offershield-ai

# 2. Create an isolated virtual environment
python -m venv venv

# 3. Activate it
#    Windows:
venv\Scripts\activate
#    macOS / Linux:
source venv/bin/activate

# 4. Install dependencies
pip install streamlit pandas pydantic python-dotenv google-genai \
            Pillow fpdf2 rapidfuzz pypdf python-whois dnspython
```

---

## 🔑 Configuration

Create a file named **`.env`** in the project root:

```env
GEMINI_API_KEY=your_gemini_api_key_here
```

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | ✅ Yes | Google Gemini API key. If missing, the app raises: `GEMINI_API_KEY is not set. Please add it to your .env file.` |

> ⚠️ **Security:** `.env` contains a live API key. **Never commit it to version control.** Add it to `.gitignore` before your first commit.

---

## ▶️ Running the App

```bash
# Activate the environment first (see Installation)
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux

# Launch
streamlit run app.py
```

Or without activating:

```bash
venv\Scripts\python.exe -m streamlit run app.py
```

**Output:**

```
You can now view your Streamlit app in your browser.

  Local URL: http://localhost:8501
  Network URL: http://172.20.10.6:8501
```

Open **http://localhost:8501** in your browser. 🎉

**Stop the app:** press `Ctrl + C` in the terminal.

---

## 🧭 Usage Guide

The app has **two main tabs**:

### 🔍 Tab 1 — Live Offer Investigation

1. **Choose an input format** using the radio buttons:

   | Mode | What to do |
   |------|-----------|
   | **Text / Email / Chat** | Paste the suspicious message into the text area (a sample scam is pre-filled). |
   | **Upload Offer Letter PDF** | Upload a multi-page PDF. Text is extracted automatically and previewed. |
   | **Upload Screenshot / Image** | Upload a PNG/JPG screenshot — analyzed visually by Gemini. |

2. Click **🚀 Analyze & Generate Audit**.

3. **Review the results:**
   - **Executive Threat Summary** — target entity, compensation, and the overall verdict card
   - **🚨 Impersonation Alert** — shown immediately if brand spoofing was detected
   - **🌐 Live Web Intelligence** — grounded company-legitimacy findings

4. **Dive into the two nested sub-tabs:**

   - **📋 Forensic Threat Vectors & Legal Redressal**
     - Explainable red-flag heatmap over the original text
     - Threat vector breakdown bars (financial / identity / process)
     - Detected warning signs & candidate safety checklist
     - Safe inquiry email draft
     - Extracted suspect payment & contact identifiers
     - Cybercrime portal draft + College placement-cell memo *(shown when score ≥ 50)*
     - **📥 Download Official Forensic Audit Report (PDF)**

   - **🤖 Observable Agent Tool & Reasoning Trace**
     - Tool dispatch counts, pipeline state, and step count
     - Chronological log of every tool call and reasoning step

### 📊 Tab 2 — Batch Benchmark & Evaluation

1. Expand **📋 Review Ground-Truth Benchmark Cases** to inspect the 8 test cases.
2. Click **⚡ Execute Full Benchmark Test** to run the full agent pipeline against every case (~8 API calls, progress bar shown).
3. Review:
   - **Metrics:** Accuracy, Precision, Recall, F1-Score, Avg Latency
   - **🔲 Confusion Matrix** (TP / FP / FN / TN)
   - **Per-case results table** with predicted labels, scores, verdicts, and latency

> Predicted label rule: score ≥ 50 → `SCAM`, otherwise → `LEGITIMATE`.

---

## 🛠️ The 4 Forensic Tools

### 1️⃣ DNS MX Resolver (`verify_domain_mx`)
Queries **MX records** for every domain found in `@email` addresses.
- ✅ Active corporate mail servers → real mail infrastructure
- ⚠️ Free-mail providers (Gmail/Yahoo/Outlook/Hotmail) → *"generic public email for formal corporate hiring"*
- ❌ No records → *"Dead domain or non-existent mail records (Likely spoofed)"*

### 2️⃣ Levenshtein Typosquatting Matcher (`detect_typosquatting`)
Compares claimed domains against a canonical employer list (`tcs.com`, `infosys.com`, `wipro.com`, `google.com`, `microsoft.com`, `amazon.com`, `deloitte.com`, …).
- **Canonical match** → confidence 100%, not impersonation
- **Trademark embedded** (e.g. `tcs-careers-portal.com`) → *Critical Impersonation*, 95% confidence
- **≥ 75% fuzzy similarity** → *High Risk Typosquatting* (e.g. `infossys.com` ≈ `infosys.com`)

### 3️⃣ WHOIS Domain Age Scanner (`lookup_domain_age_whois`)
Fetches the domain's registration/creation date.
- **< 180 days old** → flagged as `is_disposable` — *"CRITICAL: Newly Registered Scam Domain"*
- No valid WHOIS record → treated as hidden/unregistered (max risk)
- Public mail providers → skipped (age 9999)

### 4️⃣ Google Search Grounding (`conduct_web_search_grounding`)
Asks Gemini with the `GoogleSearch` tool whether the company exists, has an official career portal, or has reported scams.
- **Fallback:** if search is quota-throttled, retries as a knowledge-base query
- **Last resort:** returns a note that verification was bypassed and only deterministic heuristics were used

---

## 📐 Output Schema (`OfferAnalysis`)

All results are validated by a **Pydantic** model:

```text
OfferAnalysis
├── company_name                  # Claimed company
├── claimed_recruiter_domain      # Domain extracted from email/URL (nullable)
├── role_title                    # Offered position
├── offered_compensation          # CTC / stipend as stated
├── demands_upfront_payment       # boolean
├── payment_amount                # Extracted amount (nullable)
├── suspect_payment_handles[]     # UPI VPAs, bank details, payment links
├── suspect_contact_channels[]    # Phones, Telegram handles, unofficial emails
├── online_presence_summary       # Live web-search findings
├── financial_risk_score          # 0–100
├── identity_risk_score           # 0–100
├── process_risk_score            # 0–100
├── overall_scam_score            # 0–100 (weighted)
├── verdict                       # LEGITIMATE | SUSPICIOUS | CRITICAL_SCAM
├── red_flags[]                   # { category, evidence, severity }
│     categories: Financial Trap · Domain Anomaly · Online Verification
│                 Urgency/Coercion · Process Skips
│     severities: Low · Medium · High · Critical
├── recommended_actions[]         # Safety checklist
├── safe_response_draft           # Professional reply asking to verify, no payment
├── cybercrime_complaint_text     # Ready-to-submit grievance (cybercrime.gov.in)
└── placement_cell_report_text    # Memo for the college T&P Officer
```

**Verdict thresholds used for the verdict card:**

| Overall Score | Verdict Card |
|---------------|--------------|
| ≥ 70 | 🚨 Red — `CRITICAL_SCAM` |
| 40 – 69 | ⚠️ Amber — `SUSPICIOUS` |
| < 40 | ✅ Green — `LEGITIMATE` |

---

## 🧪 Benchmark & Evaluation Suite

8 curated real-world test cases with verified ground truth:

| ID | Ground Truth | Scenario |
|----|--------------|----------|
| TC-01 | SCAM | TCS brand impersonation + UPI "training fee" |
| TC-02 | SCAM | Infosys typosquatting (`infossys.com`) |
| TC-03 | SCAM | WhatsApp typing-job registration fee |
| TC-04 | SCAM | Generic Gmail corporate claim (Google + Telegram) |
| TC-05 | LEGITIMATE | Campus placement offer (Cognizant, official domains) |
| TC-06 | LEGITIMATE | Genuine Google internship |
| TC-07 | LEGITIMATE | Standard startup interview invitation (Zepto) |
| TC-08 | SCAM | Laptop courier deposit trap (Wipro + Telegram) |

**Metrics computed:** Accuracy, Precision, Recall, F1-Score, Avg Latency, plus a full confusion matrix.

---

## 🚨 Detection Rules

The agent is instructed to enforce these hard rules:

1. **Impersonation/typosquatting flagged** → Identity Risk **must** be 90–100% and verdict **must** be `CRITICAL_SCAM`.
2. **Upfront monetary demands** (security deposits, equipment fees, training fees, registration fees) → `CRITICAL_SCAM`.
3. **WHOIS domain < 180 days old** → red flag `[Critical] Disposable Domain Attack`.
4. **No web presence / active scam complaints** → highlight in `online_presence_summary` and raise Identity Risk.
5. **Direct selection without assessment/interview** → Process Risk **> 80**.
6. **Extract all suspect UPI VPAs, phone numbers, and Telegram channels** into `suspect_payment_handles` and `suspect_contact_channels`.

**Legal Redressal Protocol:**
- `cybercrime_complaint_text` — formal grievance for the Cyber Crime Police Cell / cybercrime.gov.in citing **§66C/66D IT Act** and relevant **BNS** cheating provisions, detailing suspect identifiers, modus operandi, and demanded amounts.
- `placement_cell_report_text` — internal incident memo for the college **Training & Placement (T&P) Officer** so they can alert the student body.

---

## 📄 Export Formats

### Forensic Audit Report (PDF)
Generated by `ForensicPDF` (built on `fpdf2`) with:

- Header banner — *OFFERSHIELD AI | FORENSIC FRAUD AUDIT REPORT*
- **Investigation Summary** — company, role, compensation, colored verdict
- **Live Web Verification Intelligence**
- **Risk Vector Decomposition** — financial / identity / process percentages
- **Forensic Evidence & Red Flags** — severity-tagged list
- **Recommended Safety Actions**
- **Recommended Candidate Reply** (monospace block)
- **Official Cybercrime Complaint Draft** — appended when score ≥ 50
- Footer with generation timestamp

> Currency and typographic characters (`₹`, `—`, smart quotes) are transliterated for Helvetica's Latin-1 charset.

### Explainable Heatmap
The original offer text rendered with `<mark>` highlights colored by category:

| Category | Color |
|----------|-------|
| Financial Trap | 🔴 Red |
| Domain Anomaly | 🟠 Orange |
| Urgency/Coercion | 🟡 Yellow |
| Process Skips | 🟣 Purple |
| Online Verification | 🔵 Blue |

Hover any highlight to see its `[Severity] Category`.

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| `GEMINI_API_KEY is not set...` | Add `GEMINI_API_KEY=...` to your `.env` file in the project root. |
| `ModuleNotFoundError: No module named 'streamlit'` | Your `venv` is empty — run `python -m pip install streamlit pandas pydantic python-dotenv google-genai Pillow fpdf2 rapidfuzz pypdf python-whois dnspython` (see Installation). Make sure the venv is activated. |
| `SyntaxError: invalid syntax` in `app.py` | A stray character may have been introduced in the source — check the reported line number. |
| WHOIS returns *"No valid WHOIS record"* | WHOIS servers rate-limit heavily; the domain may be fine. This lookup is best-effort. |
| *"Search Quota Throttled"* in the trace | Gemini search limit reached — the agent auto-falls back to knowledge-base verification. |
| Port 8501 already in use | `streamlit run app.py --server.port 8502` |
| Blank page / browser cache | Hard refresh with `Ctrl + Shift + R` |
| Slow first analysis | The agent makes 3–4 network calls (DNS + WHOIS + search + synthesis); allow 10–30 s. |
| DNS/WHOIS blocked by firewall | Corporate networks often block these; deterministic checks degrade gracefully. |

---

## 📌 Project Notes

- **Single-file design:** everything lives in `app.py` (~920 lines) for easy hand-in/demo.
- **Agent model:** `gemini-3.5-flash-lite` with `temperature=0.1` for consistent, low-variance structured output.
- **Graceful degradation:** every network tool is wrapped in `try/except` — a failed DNS/WHOIS/search lookup degrades to a deterministic heuristic instead of crashing the run.
- **Session state:** results persist across reruns (`st.session_state`), so you can explore tabs without re-running the analysis.
- **Deterministic where possible:** typosquatting and MX checks are pure functions — no LLM involved — making them reproducible and auditable.

---

## 📜 Disclaimer

OfferShield AI is an **educational / research** tool for detecting recruitment-scam patterns. Its outputs — including risk scores, verdicts, and generated legal drafts — are **AI-generated approximations**, not legal advice or a law-enforcement determination. Always verify findings independently and consult official channels (e.g., **cybercrime.gov.in**) before filing any complaint.

---

## 📄 License

No license file has been added to this project yet. If you plan to share it publicly, add a `LICENSE` file (MIT is a common choice for academic projects).

---

**Stay safe out there — never pay to get a job.** 🛡️
