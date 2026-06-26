import argparse
import hashlib
import json
from pathlib import Path


def stable_mock_score(package_name: str, current_version: str) -> float:
    key = f"{package_name}@{current_version}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def predict_is_vulnerable(record: dict) -> tuple[bool, float]:
    """Replace this mock with real PyTorch/CodeBERT inference later."""
    score = stable_mock_score(record.get("PackageName", ""), record.get("CurrentVersion", ""))
    return score >= 0.5, score


def main() -> int:
    parser = argparse.ArgumentParser(description="Mock CodeBERT inference bridge for GeminiNuGetAuditor.")
    parser.add_argument("--input", required=True, help="Path to C# exported CodeBERT inference input JSON.")
    parser.add_argument("--output", required=True, help="Path to write prediction JSON.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    payload = json.loads(input_path.read_text(encoding="utf-8-sig"))

    records = payload.get("Records", [])
    original_records = [
        item for item in records
        if item.get("AugmentationType") == "original"
    ]

    predictions = []
    for record in original_records:
        is_vulnerable, confidence = predict_is_vulnerable(record)
        package_name = record.get("PackageName", "")
        current_version = record.get("CurrentVersion", "")
        predictions.append({
            "PackageName": package_name,
            "CurrentVersion": current_version,
            "IsVulnerable": is_vulnerable,
            "CVE_ID": record.get("CVE_ID", "") if is_vulnerable else "",
            "Severity": record.get("Severity", "") if is_vulnerable else "Unknown",
            "SeverityIndonesia": severity_indonesia(record.get("Severity", "")) if is_vulnerable else "Tidak diketahui",
            "MitigationPlan": "Mock prediction. Replace with actual CodeBERT inference output.",
            "MitigationPlanIndonesia": "Prediksi mock. Ganti dengan output inference CodeBERT sebenarnya.",
            "IsGroundedInReference": False,
            "ReasoningTrace": f"Mock CodeBERT bridge prediction with confidence={confidence:.4f}.",
            "ReasoningTraceIndonesia": f"Prediksi mock bridge CodeBERT dengan confidence={confidence:.4f}."
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({
            "ModelName": "mock-codebert",
            "ProjectKey": payload.get("ProjectKey", ""),
            "VulnerabilityReports": predictions
        }, indent=2),
        encoding="utf-8"
    )
    print(f"Wrote {len(predictions)} mock CodeBERT predictions to {output_path}")
    return 0


def severity_indonesia(severity: str) -> str:
    normalized = (severity or "").strip().lower()
    return {
        "critical": "Kritis",
        "high": "Tinggi",
        "moderate": "Sedang",
        "medium": "Sedang",
        "low": "Rendah"
    }.get(normalized, "Tidak diketahui")


if __name__ == "__main__":
    raise SystemExit(main())
