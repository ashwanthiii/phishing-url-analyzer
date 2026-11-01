from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str
    points: int


RULES = [
    {
        "id": "URL001",
        "feature": "contains_at_symbol",
        "title": "At symbol detected",
        "description": "The URL contains an @ symbol, which can be used to confuse users about the actual destination.",
        "severity": "HIGH",
        "points": 20
    },
    {
        "id": "URL002",
        "feature": "uses_ip_address",
        "title": "IP address hostname",
        "description": "The URL uses an IP address instead of a conventional domain name.",
        "severity": "HIGH",
        "points": 25
    },
    {
        "id": "URL003",
        "feature": "uses_http",
        "title": "Unencrypted HTTP",
        "description": "The URL uses HTTP instead of HTTPS. This does not prove phishing, but the connection is not protected by HTTPS.",
        "severity": "LOW",
        "points": 8
    },
    {
        "id": "URL004",
        "feature": "uses_punycode",
        "title": "Punycode hostname",
        "description": "The hostname contains an xn-- label, which may represent internationalized characters.",
        "severity": "HIGH",
        "points": 20
    },
    {
        "id": "URL005",
        "feature": "has_many_subdomains",
        "title": "Excessive subdomains",
        "description": "The hostname contains an unusually high number of subdomains.",
        "severity": "MEDIUM",
        "points": 12
    },
    {
        "id": "URL006",
        "feature": "contains_suspicious_keyword",
        "title": "Suspicious keyword",
        "description": "The URL contains words commonly used in account verification or credential-related lures.",
        "severity": "MEDIUM",
        "points": 10
    },
    {
        "id": "URL007",
        "feature": "uses_url_shortener",
        "title": "URL shortener detected",
        "description": "The URL uses a known shortening service, which hides the final destination.",
        "severity": "MEDIUM",
        "points": 15
    },
    {
        "id": "URL008",
        "feature": "has_suspicious_tld",
        "title": "Uncommon top-level domain",
        "description": "The hostname uses a top-level domain included in this project's review list.",
        "severity": "MEDIUM",
        "points": 12
    },
    {
        "id": "URL009",
        "feature": "contains_many_hyphens",
        "title": "Multiple hostname hyphens",
        "description": "The hostname contains several hyphens, which may be used in deceptive domain names.",
        "severity": "LOW",
        "points": 8
    },
    {
        "id": "URL010",
        "feature": "uses_unusual_port",
        "title": "Unusual port number",
        "description": "The URL specifies a port other than the common HTTP and HTTPS ports.",
        "severity": "MEDIUM",
        "points": 10
    },
    {
        "id": "URL011",
        "feature": "contains_encoded_characters",
        "title": "Encoded URL characters",
        "description": "The URL contains percent-encoded characters. Inspect the destination carefully.",
        "severity": "LOW",
        "points": 5
    },
    {
        "id": "URL012",
        "feature": "is_long_url",
        "title": "Unusually long URL",
        "description": "The URL exceeds the configured length threshold.",
        "severity": "LOW",
        "points": 8
    }
]


def detect_threats(features):
    """
    Apply detection rules to extracted URL features.
    """

    findings = []

    for rule in RULES:
        feature_name = rule["feature"]

        if features.get(feature_name, False):
            description = rule["description"]
            points = rule["points"]

            if rule["id"] == "URL006" and "keyword_locations" in features:
                locations = features["keyword_locations"]
                points = min(
                    18,
                    (12 if locations.get("hostname") else 0)
                    + (5 if locations.get("path") else 0)
                    + (3 if locations.get("query") else 0)
                )
                found_at = []
                for key, label in (
                    ("hostname", "domain"),
                    ("path", "path"),
                    ("query", "query")
                ):
                    keywords = locations.get(key, [])
                    if keywords:
                        found_at.append(
                            label + ": " + ", ".join(keywords)
                        )

                description = (
                    "Suspicious keywords found in " + "; ".join(found_at) + "."
                )

            findings.append(
                Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    description=description,
                    severity=rule["severity"],
                    points=points
                )
            )

    return findings