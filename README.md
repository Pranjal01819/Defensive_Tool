# Deffensive_Tool
# Phishing-Link Detection Tool

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Build](https://img.shields.io/badge/build-GHActions-orange)]()

## One-liner
A lightweight, explainable phishing URL detector that exposes a REST API to analyze URLs, return a phishing prediction with confidence, and show per-feature explanations.

---

## Demo
> POST `POST /api/analyze` with `{ "url": "http://example.com" }` to get a JSON prediction.

---

## Features / What it analyzes
The detector extracts 8 simple, explainable features from each URL and uses a `RandomForestClassifier` to predict phishing probability:

1. `url_length` — total URL length (longer = more suspicious)  
2. `has_https` — whether scheme is HTTPS (HTTPS = safer)  
3. `dots_count` — number of dots in domain (subdomain abuse)  
4. `has_ip` — whether domain is an IP address (suspicious)  
5. `suspicious_keywords` — presence of words like `login`, `verify`, `account`, etc.  
6. `has_at_symbol` — presence of `@` in URL (can obfuscate domain)  
7. `hyphen_count` — many hyphens in domain (suspicious)  
8. `suspicious_tld` — suspicious TLDs (example: `tk`, `ml`, `xyz`)

(These features and logic come from `app.py`.) :contentReference[oaicite:10]{index=10}

---

## Tech stack
- Python 3.8+
- Flask
- flask-cors
- NumPy
- scikit-learn (RandomForestClassifier)
- pickle (model persistence)

---

## API Docs

### Health check
`GET /api/health`
**Response**
```json
{ "status": "healthy" }
```

**Model & Training**

The app checks for simple_phishing_model.pkl on startup. If found, it loads the model; otherwise it generates synthetic training data and trains a RandomForestClassifier and saves the model to disk. (See load_or_train_model() and generate_training_data() in app.py.) 

app
File created: simple_phishing_model.pkl

**Note: Current training uses generated/synthetic examples — consider replacing with curated, labeled URL datasets (e.g., PhishTank, OpenPhish) and retraining for production.**
