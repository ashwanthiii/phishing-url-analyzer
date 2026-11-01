# Phishing Analyzer Configuration

APP_NAME = "Phishing Analyzer"
APP_VERSION = "1.0.0"

# Risk classification thresholds
RISK_LEVELS = {
    "LOW": (0, 19),
    "MEDIUM": (20, 39),
    "HIGH": (40, 69),
    "CRITICAL": (70, 100)
}

# Suspicious URL keywords
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "signin",
    "password",
    "banking",
    "confirm",
    "wallet",
    "recover",
    "payment"
]

# Common URL shorteners
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "ow.ly"
}

# TLDs sometimes associated with abuse.
# Their presence alone does not prove a URL is malicious.
SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "country",
    "gq",
    "tk",
    "work",
    "support"
}

MAX_URL_LENGTH = 100
MAX_SUBDOMAINS = 3

POPULAR_DOMAINS = {
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "netflix.com", "instagram.com",
    "linkedin.com", "twitter.com", "whatsapp.com", "github.com",
    "outlook.com", "dropbox.com", "flipkart.com", "paytm.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com",
}