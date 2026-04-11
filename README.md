# phish-detector

> *Most phishing emails don't look suspicious. That's the point.*

`phish-detector` is a command-line tool and API that analyzes `.eml` files and classifies them as phishing or legitimate using a machine learning classifier trained on real email data. It extracts behavioral and structural features from each email — sender anomalies, URL patterns, authentication headers, body signals — and runs them through a Random Forest model.

Built as a portfolio project at the intersection of email security and applied ML.

---

## What it detects

- Brute-force phishing: mismatched domains, free providers impersonating brands, urgency language
- URL-based attacks: IP addresses instead of domains, link shorteners, open redirects, suspicious TLDs
- Header anomalies: SPF/DKIM/DMARC failures, display name mismatches
- Structural signals: hidden HTML elements, embedded forms and scripts, suspicious attachments

This detector handles common phishing patterns well. Sophisticated campaigns (compromised corporate accounts, clean domains, no attachments) require additional signals like text embeddings and domain reputation — noted in the roadmap.

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

Optional for enrichment:
- AbuseIPDB API key
- VirusTotal API key

---

## Setup

```bash
git clone https://github.com/<your-username>/phish-detector.git
cd phish-detector

uv venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

cp .env.example .env
# Add your API keys to .env
```

---

## Training the model

You need two folders of raw emails — one phishing, one legitimate.

**Recommended datasets:**
- Legitimate: [Enron corpus](https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz)
- Phishing: [SpamAssassin corpus](https://spamassassin.apache.org/old/publiccorpus/)

Place emails in:
```
data/raw/phishing/
data/raw/legitimate/
```

Then build the dataset and train:

```bash
# Build feature CSV from raw emails
uv run python build_dataset.py data/raw/phishing data/raw/legitimate data/processed/dataset.csv

# Train the classifier
uv run python src/phish_detector/cli.py train data/processed/dataset.csv
```

---

## Usage

### CLI

```bash
# Analyze a single email
phish-detector analyze path/to/email.eml

# Analyze with AbuseIPDB + VirusTotal enrichment
phish-detector analyze path/to/email.eml --enrich

# Use a custom model path
phish-detector analyze path/to/email.eml --model-path models/custom.joblib

# Train the model
phish-detector train data/processed/dataset.csv
```

### API

```bash
# Start the API server
uvicorn phish_detector.api:app --reload
```

Then send a request:

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@path/to/email.eml"
```

With enrichment:

```bash
curl -X POST "http://localhost:8000/analyze?enrich=true" \
  -F "file=@path/to/email.eml"
```

Batch analysis (up to 20 files):

```bash
curl -X POST http://localhost:8000/analyze/batch \
  -F "files=@email1.eml" \
  -F "files=@email2.eml"
```

---

## Example output

```
Verdict
┌─────────────────────────────┐
│         PHISHING            │
│   Confidence: 94.2%         │
└─────────────────────────────┘

Extracted features
╭──────────────────────────────┬───────╮
│ Feature                      │ Value │
├──────────────────────────────┼───────┤
│ urgency_word_count           │ 4     │
│ urls_with_ip                 │ 1     │
│ urls_with_shortener          │ 2     │
│ reply_to_differs_from        │ 1     │
│ spf_pass                     │ 0     │
│ dkim_pass                    │ 0     │
│ body_has_form                │ 1     │
│ has_suspicious_attachment    │ 0     │
╰──────────────────────────────┴───────╯
```

---

## How it works

**Parsing** — the `.eml` file is read and split into structured fields: sender, headers, body (plain and HTML), URLs, and attachments.

**Feature extraction** — each field is converted into numerical features the model can use. This includes sender domain analysis, URL pattern detection (IP addresses, shorteners, open redirects, suspicious TLDs), authentication header checks (SPF, DKIM, DMARC), body signals (urgency words, hidden elements, embedded forms), and attachment analysis.

**Classification** — a Random Forest classifier trained on real email data predicts the probability of phishing. The model outputs a verdict and a confidence score.

**Enrichment (optional)** — flagged URLs are checked against VirusTotal. IP addresses are checked against AbuseIPDB for abuse history.

---

## Project structure

```
phish-detector/
├── data/
│   ├── raw/
│   │   ├── phishing/       # raw phishing emails
│   │   └── legitimate/     # raw legitimate emails
│   └── processed/          # generated CSV dataset
├── src/phish_detector/
│   ├── parser.py           # .eml parsing
│   ├── features.py         # feature extraction
│   ├── model.py            # training and prediction
│   ├── integrations.py     # AbuseIPDB + VirusTotal
│   ├── cli.py              # command-line interface
│   └── api.py              # FastAPI REST API
├── tests/
├── build_dataset.py        # builds CSV from raw emails
└── README.md
```

---

## Tech stack

| Tool | Role |
|---|---|
| `scikit-learn` | Random Forest classifier |
| `joblib` | Safe model serialization |
| `beautifulsoup4` | HTML parsing and URL extraction |
| `fastapi` + `uvicorn` | REST API |
| `typer` + `rich` | CLI and terminal output |
| `requests` | AbuseIPDB and VirusTotal integration |
| `python-dotenv` | Environment variable management |

---

## Known limitations

- Trained on Enron (2001-2002) and SpamAssassin (2003) data — modern sophisticated campaigns may evade detection
- No text embeddings or semantic analysis — the model doesn't understand what the email says, only its structure
- Single-run training — no persistent model updates between analyses
- IPv6 and encoded IP formats are detected but not fully normalized

---

## Roadmap

- **Text embeddings** — use a sentence transformer to capture semantic phishing signals beyond keyword matching
- **DOM analysis** — parse the full HTML structure to detect hidden elements, pixel trackers, and form targets
- **Domain reputation** — integrate WHOIS age checks and domain reputation APIs
- **Cross-email correlation** — detect coordinated campaigns across multiple emails
- **Real-time mode** — monitor a maildir and alert on new suspicious emails
- **JSON export** — structured output for SIEM integration
