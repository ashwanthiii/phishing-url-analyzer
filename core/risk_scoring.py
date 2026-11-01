from config import RISK_LEVELS


def calculate_risk(findings):
    """
    Calculate a risk score from detected findings.
    """

    total_points = sum(finding.points for finding in findings)

    # Keep the score between 0 and 100.
    score = min(total_points, 100)

    risk_level = "LOW"

    for level, (minimum, maximum) in RISK_LEVELS.items():
        if minimum <= score <= maximum:
            risk_level = level
            break

    return {
        "score": score,
        "risk_level": risk_level,
        "total_findings": len(findings)
    }