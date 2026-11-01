from difflib import SequenceMatcher
from config import POPULAR_DOMAINS


def registered_domain(hostname):
    """Naive registered domain: last two labels (e.g. mail.google.com -> google.com).
    Note: does not handle multi-part TLDs such as .co.uk."""
    labels = hostname.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower()


def find_lookalike(hostname, threshold=0.85):
    """Return (brand_domain, similarity) if hostname resembles a popular domain."""
    domain = registered_domain(hostname)

    if domain in POPULAR_DOMAINS:
        return None  # exact match = the real brand

    best = None
    for brand in POPULAR_DOMAINS:
        ratio = SequenceMatcher(None, domain, brand).ratio()
        if ratio >= threshold and (best is None or ratio > best[1]):
            best = (brand, round(ratio, 2))
    return best