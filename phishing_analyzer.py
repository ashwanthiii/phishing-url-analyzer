import argparse
import csv
import time

from config import APP_NAME, APP_VERSION

from core.dns_check import check_dns
from core.url_parser import parse_url
from core.feature_extractor import extract_features
from core.detection_engine import detect_threats, Finding
from core.risk_scoring import calculate_risk
from core.typosquat import find_lookalike
from core.threat_intel import check_virustotal

from reports.report_generator import export_report


def analyze_url(raw_url, use_vt=False, use_dns=False):
    """
    Perform complete URL analysis.
    If use_vt is True, also look up an existing VirusTotal report.
    """

    parsed = parse_url(raw_url)

    # Do not run detection on invalid URLs.
    if not parsed.is_valid:
        return {
            "url": raw_url,
            "hostname": parsed.hostname,
            "valid": False,
            "errors": parsed.errors,
            "features": {},
            "findings": [],
            "threat_intel": None,
            "dns": None,
            "risk": {
                "score": 0,
                "risk_level": "INVALID",
                "total_findings": 0
            }
        }

    features = extract_features(parsed)
    findings = detect_threats(features)

    # Typosquatting check (offline)
    lookalike = find_lookalike(parsed.hostname)
    if lookalike:
        brand, similarity = lookalike
        findings.append(Finding(
            "URL014",
            "Possible typosquatting",
            f"The domain closely resembles '{brand}' "
            f"(similarity {similarity}). Attackers register "
            "near-identical names to impersonate brands.",
            "HIGH",
            30
        ))

    # Threat intelligence check (optional, needs VT_API_KEY)
    threat_intel = None
    if use_vt:
        threat_intel = check_virustotal(parsed.normalized_url)

        if threat_intel["status"] == "MALICIOUS":
            findings.append(Finding(
                "TI001",
                "Flagged malicious by VirusTotal",
                "Security vendors on VirusTotal flagged this URL as "
                "malicious. " + threat_intel["detail"],
                "CRITICAL",
                60
            ))
        elif threat_intel["status"] == "SUSPICIOUS":
            findings.append(Finding(
                "TI002",
                "Flagged suspicious by VirusTotal",
                "Some security vendors on VirusTotal flagged this URL. "
                + threat_intel["detail"],
                "HIGH",
                30
            ))

    dns_result = check_dns(parsed.hostname) if use_dns else None
    if dns_result and dns_result["status"] == "DOES_NOT_RESOLVE":
        findings.append(Finding(
            "DNS001",
            "Domain does not resolve",
            "The domain name does not exist in DNS, so the site is unreachable. "
            "This can mean a typo, an expired domain or a site already taken "
            "down. It does not prove the URL is safe.",
            "LOW",
            5
        ))
    elif (
        dns_result
        and dns_result["status"] == "RESOLVES"
        and any(finding.rule_id == "URL014" for finding in findings)
    ):
        findings.append(Finding(
            "DNS002",
            "Lookalike domain is registered and active",
            "The domain resembles a popular brand and exists in DNS, meaning "
            "someone registered and configured it. This is a stronger warning "
            "than a lookalike that does not exist.",
            "HIGH",
            15
        ))

    risk = calculate_risk(findings)

    return {
        "url": parsed.original_url,
        "hostname": parsed.hostname,
        "valid": True,
        "errors": [],
        "features": features,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "points": finding.points,
                **(
                    {"extra": lookalike[0]}
                    if finding.rule_id == "URL014" and lookalike
                    else {}
                )
            }
            for finding in findings
        ],
        "threat_intel": threat_intel,
        "dns": dns_result,
        "risk": risk
    }


def display_result(result, details=False):
    """
    Display URL analysis in a compact or detailed format.
    """

    print("\n" + "=" * 55)
    print("PHISHING ANALYSIS RESULT")
    print("=" * 55)

    print("URL:", result["url"])

    if not result["valid"]:
        print("\nStatus: INVALID URL")

        for error in result["errors"]:
            print("- " + error)

        print("\nNo risk score was calculated.")
        return

    print("Hostname:", result["hostname"])
    print("\nRisk Score:", result["risk"]["score"], "/ 100")
    print("Risk Level:", result["risk"]["risk_level"])

    if details:
        print("\nDetected Indicators:")
        print("-" * 55)

        if result["findings"]:
            for finding in result["findings"]:
                print("\n[" + finding["rule_id"] + "] " + finding["title"])
                print("Severity:", finding["severity"])
                print("Points:", finding["points"])
                print("Explanation:", finding["description"])
                if finding.get("extra"):
                    print(
                        "  Looks like " + finding["extra"]
                        + ". This is NOT the official site."
                    )
        else:
            print("No configured warning indicators were detected.")
    else:
        print("\nFindings:")
        if result["findings"]:
            for finding in result["findings"]:
                print("- [" + finding["rule_id"] + "] " + finding["title"])
                if finding.get("extra"):
                    print(
                        "  Looks like " + finding["extra"]
                        + ". This is NOT the official site."
                    )
        else:
            print("- No indicators detected.")

    intel = result.get("threat_intel")

    if intel:
        if details:
            print("\n" + "-" * 55)
            print("Threat Intelligence (" + intel["source"] + "):")
            print("Status:", intel["status"])
            print("Detail:", intel["detail"])
            print("Reason:", intel["reason"])
        else:
            label = "VirusTotal"
            print("\n" + label + ": " + intel["status"])
            print(" " * (len(label) + 2) + intel["reason"])

    dns_result = result.get("dns")
    if dns_result:
        if details:
            print("\nDNS Check:")
            print("Status:", dns_result["status"])
            print("Detail:", dns_result["detail"])
            print("Reason:", dns_result["reason"])
        else:
            label = "DNS"
            print("\n" + label + ": " + dns_result["status"])
            print(" " * (len(label) + 2) + dns_result["reason"])

    if details:
        print("\n" + "-" * 55)
        print("IMPORTANT:")
        print("A low risk score does NOT prove that a URL is safe.")
        if intel:
            print("Reputation data comes from an existing VirusTotal report.")
            print("'NOT_IN_DATABASE' or 'UNABLE_TO_VERIFY' does not mean safe.")
        else:
            print("This run used offline text-based analysis only.")
            print("Use --vt to add a VirusTotal reputation lookup.")
    print("=" * 55)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze URLs for potential phishing indicators."
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="URL to analyze"
    )

    parser.add_argument(
        "--file",
        help="CSV file containing URLs in a column named 'url'"
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help="Export the result to a CSV report"
    )

    parser.add_argument(
        "--vt",
        action="store_true",
        help="Check VirusTotal (requires VT_API_KEY environment variable)"
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Check whether the domain resolves in DNS (does not visit the site)"
    )

    parser.add_argument(
        "--details",
        action="store_true",
        help="Show detailed analysis explanations"
    )

    args = parser.parse_args()

    if args.file and args.url:
        parser.error("Provide either a URL or --file, not both.")

    print("=" * 55)
    print(APP_NAME, "Version", APP_VERSION)
    print("URL analysis tool" + (" + VirusTotal lookup" if args.vt else " (offline)"))
    print("=" * 55)

    def run(url):
        result = analyze_url(url, use_vt=args.vt, use_dns=args.dns)
        display_result(result, details=args.details)

        if args.report:
            path = export_report(result)
            print("\nCSV report saved:", path)

        return result

    if args.file:
        try:
            with open(args.file, newline="", encoding="utf-8-sig") as file:
                reader = csv.DictReader(file)

                if not reader.fieldnames or "url" not in reader.fieldnames:
                    parser.error("The CSV file must contain a 'url' column.")

                urls = [
                    (row.get("url") or "").strip()
                    for row in reader
                    if (row.get("url") or "").strip()
                ]
        except (OSError, UnicodeError, csv.Error) as error:
            parser.error("Could not read URL file: " + str(error))

        counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
            "INVALID": 0
        }
        previous_vt_lookup = False

        for url in urls:
            will_check_vt = args.vt and parse_url(url).is_valid
            if will_check_vt and previous_vt_lookup:
                print("Waiting 16 seconds for VirusTotal rate limit...")
                time.sleep(16)

            result = run(url)
            level = result["risk"]["risk_level"]
            counts[level] += 1

            if result.get("threat_intel") is not None:
                previous_vt_lookup = True

        print("\nBatch summary")
        print("Total URLs:", len(urls))
        for level, count in counts.items():
            print(level + ":", count)
        return

    # Single URL from the command line
    if args.url:
        run(args.url)
        return

    # Interactive mode
    while True:
        value = input("\nEnter URL (or q to quit): ").strip()

        if value.lower() in ("q", "quit", "exit"):
            print("Exiting Phishing Analyzer.")
            break

        if not value:
            print("Please enter a URL.")
            continue

        run(value)


if __name__ == "__main__":
    main()