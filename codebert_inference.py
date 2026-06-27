import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_payload(input_path: Path) -> dict:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input JSON was not found: {input_path}")

    return json.loads(input_path.read_text(encoding="utf-8-sig"))


def original_records(payload: dict) -> list[dict]:
    return [
        item for item in payload.get("Records", [])
        if item.get("AugmentationType") == "original"
    ]


def build_inference_text(record: dict) -> str:
    package_name = record.get("PackageName", "")
    current_version = record.get("CurrentVersion", "")
    snippet = record.get("CsprojSnippet", "")
    return (
        f"NuGet dependency vulnerability classification.\n"
        f"Package: {package_name}\n"
        f"Version: {current_version}\n"
        f"Project snippet: {snippet}"
    )


def load_codebert_pipeline(model_path: str):
    try:
        from transformers import pipeline
    except ImportError as exc:
        raise RuntimeError(
            "Python package 'transformers' is not installed. Install torch and transformers "
            "in the local Python environment used by CODEBERT_PYTHON."
        ) from exc

    model_directory = Path(model_path)
    if not model_directory.exists():
        raise FileNotFoundError(f"Local CodeBERT model path was not found: {model_directory}")

    print(f"Loading local CodeBERT classifier from: {model_directory}", flush=True)
    return pipeline(
        task="text-classification",
        model=str(model_directory),
        tokenizer=str(model_directory),
        device=-1,
        truncation=True,
    )


def is_vulnerable_label(label: str) -> bool:
    normalized = (label or "").strip().lower()
    return normalized in {
        "1",
        "true",
        "vulnerable",
        "vulnerability",
        "is_vulnerable",
        "label_1",
        "positive",
    }


def predict_records(payload: dict, classifier) -> list[dict]:
    records = original_records(payload)
    predictions = []

    for index, record in enumerate(records, start=1):
        package_name = record.get("PackageName", "")
        current_version = record.get("CurrentVersion", "")
        inference_text = build_inference_text(record)
        raw_result = classifier(inference_text)
        top = raw_result[0] if isinstance(raw_result, list) and raw_result else raw_result
        label = str(top.get("label", "")) if isinstance(top, dict) else ""
        score = float(top.get("score", 0.0)) if isinstance(top, dict) else 0.0
        is_vulnerable = is_vulnerable_label(label)

        print(
            f"[{index}/{len(records)}] CodeBERT local inference {package_name}@{current_version} "
            f"=> label={label} vulnerable={str(is_vulnerable).lower()} confidence={score:.4f}",
            flush=True,
        )

        predictions.append({
            "PackageName": package_name,
            "CurrentVersion": current_version,
            "IsVulnerable": is_vulnerable,
            "CVE_ID": "",
            "Severity": "Unknown",
            "SeverityIndonesia": "Tidak diketahui",
            "MitigationPlan": (
                "Local CodeBERT classifier prediction. CVE and remediation detail are not inferred "
                "by this binary classifier."
            ),
            "MitigationPlanIndonesia": (
                "Prediksi classifier CodeBERT lokal. Detail CVE dan mitigasi tidak diinferensikan "
                "oleh classifier biner ini."
            ),
            "IsGroundedInReference": False,
            "ReasoningTrace": f"Local CodeBERT label={label}; confidence={score:.4f}.",
            "ReasoningTraceIndonesia": f"CodeBERT lokal menghasilkan label={label}; confidence={score:.4f}.",
        })

    return predictions


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local real CodeBERT inference bridge for GeminiNuGetAuditor."
    )
    parser.add_argument("--input", required=True, help="Path to C# exported CodeBERT inference input JSON.")
    parser.add_argument("--output", required=True, help="Path to write CodeBERT prediction JSON.")
    parser.add_argument(
        "--model",
        default=os.environ.get("CODEBERT_MODEL_PATH", ""),
        help="Local fine-tuned CodeBERT model directory. Can also be supplied with CODEBERT_MODEL_PATH.",
    )
    args = parser.parse_args()

    if not args.model:
        raise RuntimeError(
            "No local CodeBERT model was configured. Set CODEBERT_MODEL_PATH or pass --model "
            "to a fine-tuned HuggingFace sequence-classification model directory. "
            "No synthetic predictions are generated."
        )

    input_path = Path(args.input)
    output_path = Path(args.output)

    print(f"Loading CodeBERT bridge input: {input_path}", flush=True)
    payload = load_payload(input_path)
    print(f"Loaded {len(payload.get('Records', []))} dataset record(s). Running local CodeBERT inference.", flush=True)

    classifier = load_codebert_pipeline(args.model)
    predictions = predict_records(payload, classifier)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ModelName": f"codebert-local::{Path(args.model).name}",
        "InferenceMode": "LOCAL_CODEBERT_SEQUENCE_CLASSIFICATION",
        "GeneratedAtUtc": datetime.now(timezone.utc).isoformat(),
        "ProjectKey": payload.get("ProjectKey", ""),
        "VulnerabilityReports": predictions,
    }
    output_path.write_text(json.dumps(output_payload, indent=2), encoding="utf-8")

    print(f"Wrote {len(predictions)} CodeBERT prediction(s) to {output_path}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"CodeBERT bridge failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
