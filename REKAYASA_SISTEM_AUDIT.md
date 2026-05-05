# Dokumentasi Instrumen Penelitian: RAG-Based NuGet Security Auditor

## 1. Tujuan Sistem
Membangun instrumen penelitian kuantitatif berbasis .NET 10 untuk menguji kinerja deteksi kerentanan NuGet menggunakan arsitektur Retrieval-Augmented Generation (RAG), lalu membandingkannya dengan baseline Non-RAG.

## 2. Arsitektur Solusi (Hulu ke Hilir)
1. **Extraction**: Membaca file `.csproj` untuk mengambil daftar `PackageReference`.
2. **Retrieval (RAG Part)**: Sistem mengambil referensi data keamanan nyata (local advisory file, GitHub Advisory API, fallback advisories) sebagai ground truth.
3. **Augmentation**: Menggabungkan daftar package dan konteks referensi keamanan dalam prompt terstruktur.
4. **Generation**: Gemini melakukan penilaian kerentanan package.
5. **Normalization & Persistence**: Hasil dinormalisasi (1 package = 1 report), disimpan ke JSON, lalu dibentuk metrik evaluasi dalam Excel.

## 3. Spesifikasi Teknis
- **Target Framework**: .NET 10.
- **AI Model**: Gemini (`gemini-flash-latest` secara default, configurable).
- **Guardrail Anti-Halusinasi**: Jika package tidak ditemukan pada referensi, model diarahkan untuk menandai `IsVulnerable=false`, `IsGroundedInReference=false`, dan severity Unknown.
- **Execution Mode**:
  - `--mode=rag`
  - `--mode=nonrag`
  - `--compare` (menjalankan RAG + Non-RAG pada dataset yang sama dalam satu eksekusi)

## 4. Metrik Penelitian (Performance Metrics)
Evaluasi dihitung menggunakan confusion matrix:
- **TP**: model menandai rentan dan package ada di referensi.
- **FP**: model menandai rentan tapi package tidak ada di referensi.
- **FN**: model tidak menandai rentan padahal package ada di referensi.
- **TN**: model tidak menandai rentan dan package tidak ada di referensi.

Rumus metrik:
- **Accuracy** = (TP + TN) / (TP + TN + FP + FN)
- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1-Score** = 2 × (Precision × Recall) / (Precision + Recall)

## 5. Kriteria Keberhasilan Penelitian
Sesuai tujuan mitigasi halusinasi AI, penelitian dinyatakan berhasil apabila:
1. **Precision(RAG) > Precision(Non-RAG)**
2. **FP Ratio(RAG) < FP Ratio(Non-RAG)**

dengan:
- **FP Ratio** = FP / (TP + FP)

Status komparasi pada sheet `Model Comparison`:
- `PASS` untuk tiap kriteria bila terpenuhi
- `Overall PASS` bila kedua kriteria terpenuhi
- `FAIL` bila salah satu kriteria tidak terpenuhi

## 6. Alasan Hasil Komparasi Bisa `FAIL`
Hasil `FAIL` tidak selalu berarti pipeline salah implementasi. Beberapa penyebab empiris yang umum:
1. **Baseline Non-RAG terlalu konservatif** (hampir tidak memprediksi positif), sehingga `FP` baseline = 0.
2. Jika `TP+FP` pada baseline = 0, maka `FP Ratio baseline = 0`, sehingga syarat `FP Ratio(RAG) < FP Ratio(Non-RAG)` menjadi sangat ketat.
3. Variasi respons LLM antar-run (stochasticity) dapat memengaruhi TP/FP jika parameter inferensi tidak dikunci ketat.
4. Kualitas/kelengkapan context referensi memengaruhi grounding temuan.

## 7. Artefak Output
Untuk mode compare (`--compare`), sistem menghasilkan:
- `audit-<project>-rag-<timestamp>.json`
- `audit-<project>-nonrag-<timestamp>.json`
- `metrics-<project>-compare-<timestamp>.xlsx`

Workbook compare mencakup:
- `Model Comparison`
- `RAG Summary`, `RAG Detail`, `RAG Summary Details`
- `NonRAG Summary`, `NonRAG Detail`, `NonRAG Summary Details`

## 8. Catatan Metodologis
Agar hasil komparasi lebih stabil dan representatif untuk publikasi:
1. Jalankan eksperimen berulang (misalnya 5-10 kali) pada dataset yang sama.
2. Laporkan rata-rata dan deviasi metrik.
3. Gunakan set package uji yang memiliki distribusi kasus rentan/non-rentan yang seimbang.
4. Dokumentasikan konfigurasi model, timeout, retry, dan sumber reference yang dipakai saat run.