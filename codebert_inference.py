import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def stable_mock_score(package_name: str, current_version: str) -> float:
    key = f"{package_name}@{current_version}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def predict_is_vulnerable(record: dict) -> tuple[bool, float]:
    """Deterministic local mock. Replace this with real PyTorch/CodeBERT inference later."""
    score = stable_mock_score(record.get("PackageName", ""), record.get("CurrentVersion", ""))
    return score >= 0.5, score


def severity_indonesia(severity: str) -> str:
    normalized = (severity or "").strip().lower()
    return {
        "critical": "Kritis",
        "high": "Tinggi",
        "moderate": "Sedang",
        "medium": "Sedang",
        "low": "Rendah",
    }.get(normalized, "Tidak diketahui")


def load_payload(input_path: Path) -> dict:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input JSON was not found: {input_path}")

    return json.loads(input_path.read_text(encoding="utf-8-sig"))


def build_predictions(payload: dict) -> list[dict]:
    records = payload.get("Records", [])
    original_records = [
        item for item in records
        if item.get("AugmentationType") == "original"
    ]

    predictions = []
    for index, record in enumerate(original_records, start=1):
        is_vulnerable, confidence = predict_is_vulnerable(record)
        package_name = record.get("PackageName", "")
        current_version = record.get("CurrentVersion", "")

        print(
            f"[{index}/{len(original_records)}] CodeBERT bridge inferred {package_name}@{current_version} "
            f"=> vulnerable={str(is_vulnerable).lower()} confidence={confidence:.4f}",
            flush=True,
        )

        predictions.append({
            "PackageName": package_name,
            "CurrentVersion": current_version,
            "IsVulnerable": is_vulnerable,
            "CVE_ID": record.get("CVE_ID", "") if is_vulnerable else "",
            "Severity": record.get("Severity", "") if is_vulnerable else "Unknown",
            "SeverityIndonesia": severity_indonesia(record.get("Severity", "")) if is_vulnerable else "Tidak diketahui",
            "MitigationPlan": "Mock local CodeBERT bridge prediction. Replace with actual fine-tuned CodeBERT output before using this as model-quality evidence.",
            "MitigationPlanIndonesia": "Prediksi mock bridge CodeBERT lokal. Ganti dengan output CodeBERT fine-tuned sebelum digunakan sebagai bukti kualitas model.",
            "IsGroundedInReference": False,
            "ReasoningTrace": f"Deterministic local mock CodeBERT bridge prediction with confidence={confidence:.4f}.",
            "ReasoningTraceIndonesia": f"Prediksi deterministik mock bridge CodeBERT lokal dengan confidence={confidence:.4f}.",
        })

    return predictions


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local CodeBERT inference bridge for GeminiNuGetAuditor."
    )
    parser.add_argument("--input", required=True, help="Path to C# exported CodeBERT inference input JSON.")
    parser.add_argument("--output", required=True, help="Path to write CodeBERT prediction JSON.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    print(f"Loading CodeBERT bridge input: {input_path}", flush=True)
    payload = load_payload(input_path)
    records = payload.get("Records", [])
    print(f"Loaded {len(records)} dataset record(s). Running deterministic local inference.", flush=True)

    predictions = build_predictions(payload)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ModelName": "mock-codebert-local-python-bridge",
        "InferenceMode": "MOCK_PYTHON_BRIDGE",
        "GeneratedAtUtc": datetime.now(timezone.utc).isoformat(),
        "ProjectKey": payload.get("ProjectKey", ""),
        "VulnerabilityReports": predictions,
    }
    output_path.write_text(json.dumps(output_payload, indent=2), encoding="utf-8")

    print(f"Wrote {len(predictions)} CodeBERT bridge prediction(s) to {output_path}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"CodeBERT bridge failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
