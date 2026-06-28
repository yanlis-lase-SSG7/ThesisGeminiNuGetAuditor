# Chapter 4 Experiment Summary

Ringkasan ini dibuat otomatis oleh aplikasi sebagai bahan awal Bab 4. File ini belum mengubah dokumen tesis utama.

## Execution Metadata

- GeneratedAtUtc: `2026-06-28T08:51:59.4577288+00:00`
- DatasetRoot: `D:\Project S2\yanlis-lase-SSG7\ThesisGeminiNuGetAuditor\Thesis_Dataset_1000`
- LlmProvider: `Vertex AI Gemini`
- LlmModel: `gemini-2.5-pro`
- LlmInferenceMode: `VERTEX_AI_GEMINI`
- GroundTruthProvider: `GitHub GraphQL API live`
- CodeBertProvider: `Local CodeBERT Python bridge`
- ProjectCount: `1000`
- PackageCount: `3698`
- CodeBertRecordCount: `11094`
- AllScenarioSuccessfulProjects: `1000`
- APIFailedScenarioResults: `0`
- CodeBertFailedScenarioResults: `0`
- RetrievalFailedProjects: `0`

## Aggregate Metrics

| Scenario | Total | TP | TN | FP | FN | Accuracy | Precision | Recall | F1-Score | False Positive Ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| RAG-LLM | 3698 | 585 | 3109 | 4 | 0 | 99.8918 % | 99.3209 % | 100.0000 % | 99.6593 % | 0.6791 % |
| Zero-Shot | 3698 | 374 | 2284 | 829 | 211 | 71.8767 % | 31.0889 % | 63.9316 % | 41.8345 % | 68.9111 % |
| CodeBERT | 3698 | 63 | 2712 | 401 | 522 | 75.0406 % | 13.5776 % | 10.7692 % | 12.0114 % | 86.4224 % |

## Comparative Notes

- Best F1-Score: `RAG-LLM` dengan F1 `99.6593 %`.
- Delta F1 RAG-LLM vs Zero-Shot: `+0.5782`.
- Delta F1 RAG-LLM vs CodeBERT: `+0.8765`.
- Delta Recall RAG-LLM vs Zero-Shot: `+0.3607`.
- Delta Precision RAG-LLM vs Zero-Shot: `+0.6823`.

## Interpretation Guardrails

- Ground truth hanya berasal dari GitHub GraphQL API live dan evaluasi vulnerable version range.
- Skenario dengan kegagalan Vertex AI Gemini, kegagalan retrieval, atau prediksi hilang dikeluarkan dari confusion matrix.
- Tidak ada fallback ke local advisory database, dummy data, atau ground-truth-as-prediction.
- CodeBERT dihitung hanya dari inferensi Python lokal yang berhasil menghasilkan prediction JSON.

## Generated Artifacts

- RAG-LLM JSON: `audit-rag-llm.json`
- Zero-Shot JSON: `audit-zero-shot.json`
- CodeBERT JSON: `audit-codebert.json`
- Comprehensive CSV: `audit-comprehensive-metrics.csv`
- Comprehensive Excel: `audit-comprehensive-report.xlsx`
- Interactive HTML: `audit-interactive-report.html`
- Vertex AI Gemini Diagnostics JSON: `api-diagnostics.json`
- Console Execution Log JSON: `console-execution-log.json`
