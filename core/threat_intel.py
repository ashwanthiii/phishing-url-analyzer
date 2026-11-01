import base64
import json
import os
import urllib.error
import urllib.request

VT_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{}"


def _vt_url_id(url):
    # VirusTotal identifies a URL by its URL-safe base64, without padding.
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _result(status, detail, reason, stats=None):
    return {"source": "VirusTotal", "status": status,
            "detail": detail, "reason": reason, "stats": stats or {}}


def check_virustotal(url, timeout=10):
    """
    Look up an existing VirusTotal report. This only READS a report;
    it never submits the URL for scanning.
    Statuses: MALICIOUS, SUSPICIOUS, NO_KNOWN_THREAT, NOT_IN_DATABASE,
              UNABLE_TO_VERIFY
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return _result(
            "UNABLE_TO_VERIFY",
            "VT_API_KEY environment variable not set.",
            "No VT_API_KEY was found, so no reputation check was done."
        )

    request = urllib.request.Request(
        VT_ENDPOINT.format(_vt_url_id(url)),
        headers={"x-apikey": api_key, "accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return _result(
                "NOT_IN_DATABASE",
                "VirusTotal has no report for this URL.",
                "VirusTotal has no report for this URL. It may be new or never scanned."
            )
        if error.code == 401:
            return _result(
                "UNABLE_TO_VERIFY",
                "API key rejected (HTTP 401).",
                "VirusTotal could not be reached or returned an error."
            )
        if error.code == 429:
            return _result(
                "UNABLE_TO_VERIFY",
                "Rate limit reached (free tier: 4 requests/minute).",
                "VirusTotal's free limit (4 lookups per minute) was reached. "
                "Wait a minute and retry."
            )
        return _result(
            "UNABLE_TO_VERIFY",
            f"HTTP error {error.code}.",
            "VirusTotal could not be reached or returned an error."
        )
    except (urllib.error.URLError, TimeoutError):
        return _result(
            "UNABLE_TO_VERIFY",
            "Network error or timeout.",
            "VirusTotal could not be reached or returned an error."
        )
    except json.JSONDecodeError:
        return _result(
            "UNABLE_TO_VERIFY",
            "Invalid response from VirusTotal.",
            "VirusTotal could not be reached or returned an error."
        )

    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    detail = f"{malicious} malicious, {suspicious} suspicious vendor detections."

    if malicious >= 3:
        return _result(
            "MALICIOUS",
            detail,
            "Security vendors on VirusTotal have flagged this URL. Do not open it.",
            stats
        )
    if malicious > 0 or suspicious > 0:
        return _result(
            "SUSPICIOUS",
            detail,
            "Security vendors on VirusTotal have flagged this URL. Do not open it.",
            stats
        )
    return _result(
        "NO_KNOWN_THREAT",
        detail,
        "No vendor has flagged it so far. New phishing sites are often not "
        "reported yet, so this does not mean it is safe.",
        stats
    )