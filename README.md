# phish-detector

A tool that reads an email file and tells you if it's phishing or not.

It doesn't use rules someone wrote by hand. It was trained on real emails — thousands of legitimate ones from the Enron corpus and hundreds of phishing samples from the SpamAssassin corpus — and learned what separates them. Things like whether the sender domain matches the reply-to, whether there are links pointing to IP addresses instead of domain names, whether the email is trying to scare you into clicking something.

It's not perfect. A well-crafted phishing email from a compromised corporate account with a clean link will probably pass. That's a known limitation and it's in the roadmap.

---

## What it looks at

- Who sent it and whether the reply-to points somewhere else
- The URLs — are any of them IP addresses, shorteners, or redirects in disguise
- Whether SPF, DKIM, and DMARC passed
- Words that create urgency or fear
- Hidden elements, embedded forms, suspicious attachments

---

## Setup

```bash
git clone https://github.com/<your-username>/phish-detector.git
cd phish-detector

uv venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

cp .env.example .env
```

If you want URL and IP enrichment, add your keys to `.env`:
```
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
```

---

## Training

You need emails. Two folders — one phishing, one legitimate.

Good sources:
- Legitimate: [Enron corpus](https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz)
- Phishing: [SpamAssassin corpus](https://spamassassin.apache.org/old/publiccorpus/)

Drop them in `data/raw/phishing/` and `data/raw/legitimate/`, then:

```bash
uv run python build_dataset.py data/raw/phishing data/raw/legitimate data/processed/dataset.csv
uv run python src/phish_detector/cli.py train data/processed/dataset.csv
```

---

## Using it

### From the terminal

```bash
# analyze an email
phish-detector analyze path/to/email.eml

# with external enrichment (AbuseIPDB + VirusTotal)
phish-detector analyze path/to/email.eml --enrich
```

### As an API

```bash
uvicorn phish_detector.api:app --reload
```

```bash
# single email
curl -X POST http://localhost:8000/analyze -F "file=@email.eml"

# up to 20 at once
curl -X POST http://localhost:8000/analyze/batch \
  -F "files=@email1.eml" -F "files=@email2.eml"
```

The API exists so other systems can send emails for analysis without touching the CLI — useful if you want to plug this into a mail server or a larger pipeline.

---

## Example output

```
╭──────────────╮
│   PHISHING   │
│  94.2% sure  │
╰──────────────╯

╭──────────────────────────────┬───────╮
│ reply_to_differs_from        │ 1     │
│ urls_with_ip                 │ 1     │
│ urls_with_shortener          │ 2     │
│ urgency_word_count           │ 4     │
│ spf_pass                     │ 0     │
│ body_has_form                │ 1     │
╰──────────────────────────────┴───────╯
```

---

## Stack

`scikit-learn` for the model, `joblib` for serialization (not pickle — it's a known attack vector), `beautifulsoup4` for HTML parsing, `fastapi` for the API, `typer` and `rich` for the CLI.

---

## Structure

```
phish-detector/
├── data/raw/           # your email files go here
├── data/processed/     # generated dataset CSV
├── src/phish_detector/
│   ├── parser.py       # reads the .eml
│   ├── features.py     # turns it into numbers
│   ├── model.py        # trains and predicts
│   ├── integrations.py # AbuseIPDB + VirusTotal
│   ├── cli.py          # terminal interface
│   └── api.py          # REST API
└── build_dataset.py    # generates the CSV from raw emails
```

---

## Limitations

The model was trained on data from 2001-2003. It catches the obvious stuff. A modern campaign that uses a clean domain, no attachments, and a legitimate-looking sender will probably get through. The roadmap includes text embeddings and domain reputation checks to close that gap.

---

## Roadmap

- Semantic analysis with sentence transformers — understand what the email is actually saying
- DOM analysis — look at the full HTML structure, not just whether a form tag exists
- Domain age and reputation checks via WHOIS
- Incremental training — update the model without retraining from scratch
- JSON export for SIEM integration
