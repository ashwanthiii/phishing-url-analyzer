# Phishing Analyzer

An advanced Python-based cybersecurity project that analyzes
URLs and identifies potential phishing indicators using
explainable rule-based detection.

## 1. Project Overview

Phishing Analyzer analyzes URLs and identifies suspicious
characteristics commonly associated with phishing.

It parses URLs, extracts relevant features, applies detection
rules, calculates a risk score, and explains the detected
indicators. Optional VirusTotal lookups read existing reports;
the application does not submit URLs for scanning.

The project does not open or crawl URLs.

## 2. Features

- URL parsing and validation
- IP address hostname detection
- HTTP scheme detection
- Punycode hostname detection
- Suspicious keyword detection
- Keyword location detection in the hostname, path, and query
- URL shortener detection
- Excessive subdomain detection
- Suspicious top-level domain detection
- Unusual port detection
- Encoded character detection
- URL length analysis
- Typosquatting detection using `difflib` and `POPULAR_DOMAINS` in `config.py`
- Optional VirusTotal lookup with `--vt` and the `VT_API_KEY` environment variable
- Explainable detection rules
- Risk scoring from 0 to 100
- Four risk classifications
- CSV report generation
- Batch analysis from a CSV file
- Automated unit testing

## 3. Technology Stack

- Python
- Regular expressions and URL parsing
- ipaddress
- dataclasses
- CSV
- argparse
- unittest

## 4. Project Structure

Phishing-Analyzer/
│
├── phishing_analyzer.py
├── config.py
├── README.md
├── requirements.txt
│
├── core/
│   ├── __init__.py
│   ├── url_parser.py
│   ├── feature_extractor.py
│   ├── detection_engine.py
│   ├── risk_scoring.py
│   ├── typosquat.py
│   └── threat_intel.py
│
├── reports/
│   ├── __init__.py
│   └── report_generator.py
│
├── tests/
│   ├── test_parser.py
│   ├── test_detection.py
│   ├── test_scoring.py
│   └── test_threat_intel.py
│
├── data/
│   └── sample_urls.csv
│
└── screenshots/

## 5. Installation

Install Python 3.10 or later.

Clone or download this repository.

No third-party dependencies are required.

## 6. Running the Project

Open the project directory in the terminal.

Run:

python phishing_analyzer.py

Enter a URL when prompted.

Type q to quit.

## 7. Command-Line Usage

Analyze a URL:

python phishing_analyzer.py https://example.com

Analyze a URL and export a CSV report:

python phishing_analyzer.py https://example.com --report

Analyze a URL and check its existing VirusTotal report:

python phishing_analyzer.py https://example.com --vt

Include DNS checks with compact output:

python phishing_analyzer.py https://example.com --dns

Show detailed finding explanations and check reasons:

python phishing_analyzer.py https://example.com --dns --details

Analyze a URL, check VirusTotal, and export a CSV report:

python phishing_analyzer.py https://example.com --vt --report

Analyze URLs from a CSV file with a `url` column:

python phishing_analyzer.py --file data/sample_urls.csv

Analyze a CSV file, check VirusTotal, and export each result:

python phishing_analyzer.py --file data/sample_urls.csv --vt --report

Use detailed output for a CSV batch:

python phishing_analyzer.py --file data/sample_urls.csv --dns --details

Run the interactive analyzer:

python phishing_analyzer.py

## 8. Setting up VirusTotal

1. Create a free account at [VirusTotal](https://www.virustotal.com/).
2. Obtain your API key from your account profile.
3. Set the key in PowerShell for the current terminal session:

   ```powershell
   $env:VT_API_KEY = "your_api_key_here"
   ```

4. Run the analyzer with `--vt`, for example:

   ```powershell
   python phishing_analyzer.py https://example.com --vt
   ```

Never commit your API key or add it to source files. Keep it private.

## 9. Running Tests

Run all automated tests:

python -m unittest discover -s tests -v

## 10. Risk Classification

| Score | Classification |
|---|---|
| 0–19 | Low |
| 20–39 | Medium |
| 40–69 | High |
| 70–100 | Critical |

Risk scores are heuristic indicators, not probabilities.

## 11. Limitations

- It does not visit or crawl websites.
- Typosquatting detection uses a naive registered-domain check based on the last two hostname labels; it does not support multi-part suffixes such as `.co.uk`.
- The typosquatting comparison only covers the brands listed in `POPULAR_DOMAINS` in `config.py`.
- VirusTotal lookups require a `VT_API_KEY` environment variable.
- The free VirusTotal tier allows 4 requests per minute. Batch lookups wait between requests when `--vt` is used.
- VirusTotal lookups only retrieve reports for URLs that have already been reported; the application does not submit URLs for scanning.
- `NO_KNOWN_THREAT` means VirusTotal returned no malicious or suspicious detections in the existing report; it does not mean the URL is safe.
- It does not verify SSL certificates.
- A low score does not prove a URL is safe.
- A suspicious indicator does not prove a URL is malicious.

## 12. Screenshots

### Phishing Analyzer result

![Phishing Analyzer result placeholder](screenshots/paypa1_result.png)

### Tests passing

![Tests passing placeholder](screenshots/tests_passing.png)

## 13. Ethical Use

Use this application for cybersecurity education,
authorized security analysis, and awareness.

Do not use it to target systems or individuals without
permission.

## 14. Future Improvements

- More advanced domain analysis
- HTML dashboard
- Additional detection rules
- PDF report generation

## 15. Author

Add your name and contact information here.