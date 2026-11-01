import csv
import os
from datetime import datetime


def export_report(result, output_file="reports/analysis_report.csv"):
    """
    Export one URL analysis result to a CSV report.
    """

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    file_exists = (
        os.path.isfile(output_file)
        and os.path.getsize(output_file) > 0
    )

    with open(
        output_file,
        mode="a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "url",
                "hostname",
                "valid",
                "risk_score",
                "risk_level",
                "finding_count",
                "findings",
                "vt_status",
                "vt_detail"
            ]
        )

        if not file_exists:
            writer.writeheader()

        intel = result.get("threat_intel") or {}
        finding_text = " | ".join(
            finding["title"]
            for finding in result["findings"]
        )

        writer.writerow({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "url": result["url"],
            "hostname": result["hostname"],
            "valid": result["valid"],
            "risk_score": result["risk"]["score"],
            "risk_level": result["risk"]["risk_level"],
            "finding_count": result["risk"]["total_findings"],
            "findings": finding_text or "No indicators detected",
            "vt_status": intel.get("status", "NOT_CHECKED"),
            "vt_detail": intel.get("detail", "")
        })

    return output_file