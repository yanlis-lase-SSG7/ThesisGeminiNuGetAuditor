import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_ENCODER_MODEL = "microsoft/codebert-base"


def load_payload(input_path: Path) -> dict:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input JSON was not found: {input_path}")

    return json.loads(input_path.read_text(encoding="utf-8-sig"))


def original_records(payload: dict) -> list[dict]:
    return [
        item for item in payload.get("Records", [])
        if item.get("AugmentationType") == "original"
    ]


def labeled_training_records(payload: dict) -> list[dict]:
    records = payload.get("Records", [])
    training = [item for item in records if item.get("Split") == "training"]
    if has_two_classes(training):
        return training

    validation = [item for item in records if item.get("Split") in {"training", "validation"}]
    if has_two_classes(validation):
        return validation

    return records


def has_two_classes(records: list[dict]) -> bool:
    labels = {int(bool(item.get("Label", False))) for item in records}
    return labels == {0, 1}


def build_inference_text(record: dict) -> str:
    package_name = record.get("PackageName", "")
    current_version = record.get("CurrentVersion", "")
    mutated_name = record.get("MutatedPackageName", package_name)
    mutated_version = record.get("MutatedVersion", current_version)
    snippet = record.get("CsprojSnippet", "")
    return (
        "NuGet dependency vulnerability classification.\n"
        f"Package: {package_name}\n"
        f"Version: {current_version}\n"
        f"Candidate package text: {mutated_name}@{mutated_version}\n"
        f"Project snippet: {snippet}"
    )


def load_sequence_classifier(model_path: str):
    try:
        import torch
        from transformers import pipeline
    except ImportError as exc:
        raise RuntimeError(
            "Python package 'transformers' is not installed. Install CodeBERT dependencies "
            "in the local Python environment used by CODEBERT_PYTHON."
        ) from exc

    model_directory = Path(model_path)
    if not model_directory.exists():
        raise FileNotFoundError(f"Local CodeBERT model path was not found: {model_directory}")

    device = 0 if torch.cuda.is_available() else -1
    device_name = "cuda:0" if device == 0 else "cpu"
    print(f"Loading local fine-tuned CodeBERT classifier from: {model_directory} on {device_name}", flush=True)
    return pipeline(
        task="text-classification",
        model=str(model_directory),
        tokenizer=str(model_directory),
        device=device,
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


def predict_with_sequence_classifier(payload: dict, classifier) -> list[dict]:
    records = original_records(payload)
    predictions = []

    for index, record in enumerate(records, start=1):
        package_name = record.get("PackageName", "")
        current_version = record.get("CurrentVersion", "")
        raw_result = classifier(build_inference_text(record))
        top = raw_result[0] if isinstance(raw_result, list) and raw_result else raw_result
        label = str(top.get("label", "")) if isinstance(top, dict) else ""
        score = float(top.get("score", 0.0)) if isinstance(top, dict) else 0.0
        is_vulnerable = is_vulnerable_label(label)

        print(
            f"[{index}/{len(records)}] CodeBERT classifier {package_name}@{current_version} "
            f"=> label={label} vulnerable={str(is_vulnerable).lower()} confidence={score:.4f}",
            flush=True,
        )

        predictions.append(build_prediction(record, is_vulnerable, score, f"label={label}"))

    return predictions


def import_embedding_dependencies():
    try:
        import numpy as np
        import torch
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "CodeBERT embedding baseline requires local Python packages: torch, transformers, "
            "scikit-learn, and numpy. Install them in the Python environment used by CODEBERT_PYTHON."
        ) from exc

    return np, torch, LogisticRegression, make_pipeline, StandardScaler, AutoModel, AutoTokenizer


def encode_texts(texts: list[str], tokenizer, model, torch, np, batch_size: int, max_length: int):
    vectors = []
    model.eval()
    device = next(model.parameters()).device
    with torch.no_grad():
        for start in range(0, len(texts), batch_size):
            batch = texts[start:start + batch_size]
            encoded = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            encoded = {key: value.to(device) for key, value in encoded.items()}
            output = model(**encoded)
            mask = encoded["attention_mask"].unsqueeze(-1)
            token_embeddings = output.last_hidden_state * mask
            summed = token_embeddings.sum(dim=1)
            counts = mask.sum(dim=1).clamp(min=1)
            pooled = summed / counts
            vectors.append(pooled.cpu().numpy())

    return np.vstack(vectors)


def load_embedding_context(encoder_model: str) -> dict:
    np, torch, LogisticRegression, make_pipeline, StandardScaler, AutoModel, AutoTokenizer = import_embedding_dependencies()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Loading CodeBERT encoder: {encoder_model} on {device}", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(encoder_model)
    model = AutoModel.from_pretrained(encoder_model)
    model.to(device)

    return {
        "np": np,
        "torch": torch,
        "LogisticRegression": LogisticRegression,
        "make_pipeline": make_pipeline,
        "StandardScaler": StandardScaler,
        "tokenizer": tokenizer,
        "model": model,
    }


def predict_with_embedding_classifier_context(payload: dict, context: dict, batch_size: int, max_length: int) -> list[dict]:
    np = context["np"]
    torch = context["torch"]
    LogisticRegression = context["LogisticRegression"]
    make_pipeline = context["make_pipeline"]
    StandardScaler = context["StandardScaler"]
    tokenizer = context["tokenizer"]
    model = context["model"]
    train_records = labeled_training_records(payload)
    prediction_records = original_records(payload)

    if not prediction_records:
        raise RuntimeError("No original CodeBERT records were found for inference.")

    if not has_two_classes(train_records):
        labels = {int(bool(item.get("Label", False))) for item in train_records}
        if labels == {0}:
            print(
                "Training labels contain only non-vulnerable records. "
                "Using a constant non-vulnerable CodeBERT baseline for this project.",
                flush=True,
            )
            return [
                build_prediction(record, False, 1.0, "single-class-non-vulnerable-baseline")
                for record in prediction_records
            ]

        raise RuntimeError(
            "CodeBERT local training requires at least one labeled record. "
            "The current project dataset is empty or invalid."
        )

    train_texts = [build_inference_text(record) for record in train_records]
    train_labels = np.array([int(bool(record.get("Label", False))) for record in train_records])
    train_package_names = np.array([
        str(record.get("PackageName", "")).lower()
        for record in train_records
    ])
    predict_texts = [build_inference_text(record) for record in prediction_records]

    print(
        f"Encoding {len(train_records)} labeled CodeBERT record(s) for leave-one-package-out local classification.",
        flush=True,
    )
    x_train = encode_texts(train_texts, tokenizer, model, torch, np, batch_size, max_length)

    print(f"Running CodeBERT embedding inference for {len(prediction_records)} original package record(s).", flush=True)
    x_predict = encode_texts(predict_texts, tokenizer, model, torch, np, batch_size, max_length)

    predictions = []
    for index, record in enumerate(prediction_records, start=1):
        package_name = record.get("PackageName", "")
        current_version = record.get("CurrentVersion", "")
        current_package = str(package_name).lower()
        train_mask = train_package_names != current_package
        scoped_labels = train_labels[train_mask]

        if set(scoped_labels.tolist()) == {0, 1}:
            classifier = make_pipeline(
                StandardScaler(),
                LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42),
            )
            classifier.fit(x_train[train_mask], scoped_labels)
            probabilities = classifier.predict_proba(x_predict[index - 1:index])
            positive_index = list(classifier.classes_).index(1)
            score = float(probabilities[0][positive_index])
            is_vulnerable = score >= 0.5
            evidence = "leave-one-package-out-embedding-logreg"
        elif len(scoped_labels) > 0 and int(scoped_labels[0]) == 1:
            score = 1.0
            is_vulnerable = True
            evidence = "single-class-after-package-exclusion-vulnerable"
        else:
            score = 1.0
            is_vulnerable = False
            evidence = "single-class-after-package-exclusion-non-vulnerable"

        print(
            f"[{index}/{len(prediction_records)}] CodeBERT embedding classifier {package_name}@{current_version} "
            f"=> vulnerable={str(is_vulnerable).lower()} confidence={score:.4f}",
            flush=True,
        )
        predictions.append(build_prediction(record, is_vulnerable, score, evidence))

    return predictions


def predict_with_embedding_classifier(payload: dict, encoder_model: str, batch_size: int, max_length: int) -> list[dict]:
    context = load_embedding_context(encoder_model)
    return predict_with_embedding_classifier_context(payload, context, batch_size, max_length)


def is_batch_payload(payload: dict) -> bool:
    return isinstance(payload.get("Projects"), list)


def batch_projects(payload: dict) -> list[dict]:
    if is_batch_payload(payload):
        return payload.get("Projects", [])

    return [payload]


def build_project_output(project_payload: dict, predictions: list[dict], model_name: str, inference_mode: str) -> dict:
    return {
        "ModelName": model_name,
        "InferenceMode": inference_mode,
        "GeneratedAtUtc": datetime.now(timezone.utc).isoformat(),
        "ProjectKey": project_payload.get("ProjectKey", ""),
        "VulnerabilityReports": predictions,
    }


def build_prediction(record: dict, is_vulnerable: bool, confidence: float, evidence: str) -> dict:
    return {
        "PackageName": record.get("PackageName", ""),
        "CurrentVersion": record.get("CurrentVersion", ""),
        "IsVulnerable": bool(is_vulnerable),
        "CVE_ID": "",
        "Severity": "Unknown",
        "SeverityIndonesia": "Tidak diketahui",
        "MitigationPlan": (
            "Local CodeBERT prediction. CVE and remediation detail are intentionally not inferred "
            "by this classifier."
        ),
        "MitigationPlanIndonesia": (
            "Prediksi CodeBERT lokal. Detail CVE dan mitigasi sengaja tidak diinferensikan "
            "oleh classifier ini."
        ),
        "IsGroundedInReference": False,
        "ReasoningTrace": f"Local CodeBERT evidence={evidence}; confidence={confidence:.4f}.",
        "ReasoningTraceIndonesia": f"CodeBERT lokal evidence={evidence}; confidence={confidence:.4f}.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local real CodeBERT inference bridge for GeminiNuGetAuditor."
    )
    parser.add_argument("--input", required=True, help="Path to C# exported CodeBERT inference input JSON.")
    parser.add_argument("--output", required=True, help="Path to write CodeBERT prediction JSON.")
    parser.add_argument(
        "--model",
        default=os.environ.get("CODEBERT_MODEL_PATH", ""),
        help="Optional local fine-tuned CodeBERT sequence-classification model directory.",
    )
    parser.add_argument(
        "--encoder",
        default=os.environ.get("CODEBERT_ENCODER_MODEL", DEFAULT_ENCODER_MODEL),
        help="CodeBERT encoder model for automatic local embedding baseline when --model is not supplied.",
    )
    parser.add_argument("--batch-size", type=int, default=8, help="Embedding inference batch size.")
    parser.add_argument("--max-length", type=int, default=256, help="Maximum tokenizer sequence length.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    print(f"Loading CodeBERT bridge input: {input_path}", flush=True)
    payload = load_payload(input_path)
    projects = batch_projects(payload)
    record_count = sum(len(project.get("Records", [])) for project in projects)
    print(
        f"Loaded {len(projects)} project payload(s) and {record_count} dataset record(s). "
        "Running local CodeBERT inference.",
        flush=True,
    )

    outputs = []

    if args.model:
        classifier = load_sequence_classifier(args.model)
        model_name = f"codebert-local-sequence-classifier::{Path(args.model).name}"
        inference_mode = "LOCAL_CODEBERT_SEQUENCE_CLASSIFICATION"
        for project_index, project_payload in enumerate(projects, start=1):
            print(
                f"[Batch {project_index}/{len(projects)}] Running fine-tuned CodeBERT classifier "
                f"for project {project_payload.get('ProjectKey', '')}",
                flush=True,
            )
            predictions = predict_with_sequence_classifier(project_payload, classifier)
            outputs.append(build_project_output(project_payload, predictions, model_name, inference_mode))
    else:
        model_name = f"codebert-embedding-logreg::{args.encoder}"
        inference_mode = "LOCAL_CODEBERT_EMBEDDING_LOGREG"
        context = load_embedding_context(args.encoder)
        for project_index, project_payload in enumerate(projects, start=1):
            print(
                f"[Batch {project_index}/{len(projects)}] Running CodeBERT embedding classifier "
                f"for project {project_payload.get('ProjectKey', '')}",
                flush=True,
            )
            predictions = predict_with_embedding_classifier_context(
                project_payload,
                context,
                args.batch_size,
                args.max_length,
            )
            outputs.append(build_project_output(project_payload, predictions, model_name, inference_mode))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_payload = (
        {
            "ModelName": model_name,
            "InferenceMode": inference_mode,
            "GeneratedAtUtc": datetime.now(timezone.utc).isoformat(),
            "Projects": outputs,
        }
        if is_batch_payload(payload)
        else outputs[0]
    )
    output_path.write_text(json.dumps(output_payload, indent=2), encoding="utf-8")

    prediction_count = sum(len(item.get("VulnerabilityReports", [])) for item in outputs)
    print(
        f"Wrote {prediction_count} CodeBERT prediction(s) for {len(outputs)} project(s) to {output_path}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"CodeBERT bridge failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
