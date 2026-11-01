from config import (
    SUSPICIOUS_KEYWORDS,
    URL_SHORTENERS,
    SUSPICIOUS_TLDS,
    MAX_URL_LENGTH,
    MAX_SUBDOMAINS
)


def extract_features(parsed):
    """
    Extract measurable features from a parsed URL.
    """

    hostname = parsed.hostname.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    labels = hostname.split(".") if hostname else []

    subdomain_count = max(0, len(labels) - 2)

    tld = labels[-1] if len(labels) >= 2 else ""

    keyword_locations = {
        "hostname": [
            keyword for keyword in SUSPICIOUS_KEYWORDS
            if keyword in hostname
        ],
        "path": [
            keyword for keyword in SUSPICIOUS_KEYWORDS
            if keyword in path
        ],
        "query": [
            keyword for keyword in SUSPICIOUS_KEYWORDS
            if keyword in query
        ]
    }

    features = {
        "url_length": len(parsed.original_url),

        "contains_at_symbol": "@" in parsed.normalized_url,

        "uses_ip_address": parsed.is_ip_address,

        "uses_http": parsed.scheme == "http",

        "uses_punycode": "xn--" in hostname,

        "subdomain_count": subdomain_count,

        "has_many_subdomains": subdomain_count > MAX_SUBDOMAINS,

        "contains_suspicious_keyword": any(keyword_locations.values()),

        "keyword_locations": keyword_locations,

        "uses_url_shortener": hostname in URL_SHORTENERS,

        "has_suspicious_tld": tld in SUSPICIOUS_TLDS,

        "contains_many_hyphens": hostname.count("-") >= 3,

        "uses_unusual_port": (
            parsed.port is not None
            and parsed.port not in (80, 443)
        ),

        "contains_encoded_characters": "%" in parsed.normalized_url,

        "is_long_url": len(parsed.original_url) > MAX_URL_LENGTH
    }

    return features