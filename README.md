# GeminiNuGetAuditor

`GeminiNuGetAuditor` adalah aplikasi console berbasis `.NET 10` untuk melakukan audit keamanan dependency NuGet pada file `.csproj`. Sistem ini mendukung eksperimen komparatif sesuai metodologi tesis: **RAG-LLM**, **Zero-Shot**, dan **CodeBERT baseline**.

## Tujuan Project

Project ini dibuat untuk:

- mengekstraksi daftar package NuGet dan versi dari file `.csproj`;
- mengambil data ground truth kerentanan dari GitHub Advisory Database secara real-time;
- menjalankan skenario **RAG-LLM** dengan Gemini 1.5 Pro yang diperkuat konteks advisory;
- menjalankan skenario **Zero-Shot** dengan Gemini 1.5 Pro tanpa konteks eksternal untuk mengukur halusinasi dan risiko Slopsquatting;
- menyiapkan dataset baseline **CodeBERT** melalui augmentasi data dan split 70% training, 15% validation, dan 15% testing;
- menghitung metrik evaluasi berbasis confusion matrix: TP, TN, FP, FN, Accuracy, Precision, Recall, dan F1-Score;
- menghasilkan artefak JSON, CSV, dan Excel untuk kebutuhan analisis penelitian.

## Business Flow Singkat

Alur bisnis utama sistem adalah sebagai berikut:

1. User menentukan file `.csproj` yang akan diaudit.
2. Aplikasi membaca seluruh `PackageReference` dari file tersebut.
3. Aplikasi mengambil referensi keamanan dengan prioritas:
   - **Priority 1: GitHub GraphQL API** sebagai sumber real-time;
   - **Fallback 1: Local OSV/GitHub Advisory Database** melalui `github-advisory-db.json`;
   - **Fallback 2: sample advisories** dari `appsettings.json`.
4. Aplikasi membentuk ground truth label dari referensi keamanan yang berhasil digunakan.
5. Pada mode RAG-LLM, daftar package dan konteks advisory dimasukkan ke prompt Gemini.
6. Pada mode Zero-Shot, daftar package dikirim ke Gemini tanpa konteks advisory eksternal.
7. Pada mode CodeBERT, aplikasi mengekspor dataset JSON/CSV yang sudah diaugmentasi dan dibagi menjadi training, validation, dan testing.
8. Hasil prediksi dibandingkan dengan ground truth untuk menghasilkan metrik evaluasi.

## Detail Alur

### 1. Extraction

`CsprojPackageExtractor.cs` membaca file `.csproj` secara null-safe dan mengambil:

- `PackageName`
- `CurrentVersion`

Extractor mendukung versi pada atribut `Version` maupun child element `<Version>`.

### 2. Retrieval Ground Truth

`SecurityReferenceProvider.cs` menerapkan retrieval berlapis dengan urutan final:

1. **GitHub GraphQL API (Real-time)**  
   Sistem memanggil GitHub Advisory Database melalui GraphQL untuk setiap package NuGet. Sumber ini menjadi prioritas utama karena paling mutakhir.

2. **Local OSV Database / GitHub Advisory JSON (Fallback 1)**  
   Jika GitHub API gagal karena timeout, rate-limit, konfigurasi token, HTTP error, atau respons tidak valid, sistem membaca file lokal `github-advisory-db.json`.

3. **Appsettings Fallback (Fallback 2)**  
   Jika file lokal hilang, tidak dapat dibaca, atau JSON rusak, sistem memakai sample advisories pada `SecurityReference:FallbackAdvisories`.

Setiap tahap menulis diagnostics ke console, termasuk sumber yang akhirnya dipakai.

### 3. Inference Scenarios

Sistem mendukung tiga skenario evaluasi:

- **RAG-LLM (`--mode=rag`)**  
  Gemini 1.5 Pro menerima daftar package dan konteks advisory. Model hanya boleh menandai rentan jika temuan didukung referensi.

- **Zero-Shot (`--mode=zero-shot`)**  
  Gemini 1.5 Pro menerima daftar package tanpa konteks eksternal. Skenario ini dipakai untuk mengukur kecenderungan halusinasi dan false positive.

- **CodeBERT (`--mode=codebert --export-codebert-dataset`)**  
  Sistem menyiapkan dataset baseline deep learning untuk fine-tuning/evaluasi CodeBERT.

Mode komparasi:

```powershell
dotnet run -- --compare "path\to\project.csproj"
```

### 4. JSON Output Gemini

Gemini dipaksa mengembalikan JSON murni sesuai model `GeminiResponse`. Setiap report berisi field bilingual:

- `Severity` dan `SeverityIndonesia`
- `MitigationPlan` dan `MitigationPlanIndonesia`
- `ReasoningTrace` dan `ReasoningTraceIndonesia`

## Input dan Output

### Input

- path file `.csproj`;
- Gemini API key melalui `GEMINI_API_KEY` atau `Gemini:ApiKey`;
- GitHub token melalui `GITHUB_TOKEN` atau `SecurityReference:GitHubToken`;
- konfigurasi `SecurityReference` pada `appsettings.json`;
- optional local database `github-advisory-db.json`.

### Output

- `audit-<project>-rag-llm-<timestamp>.json`
- `audit-<project>-zero-shot-<timestamp>.json`
- `metrics-<project>-<mode>-<timestamp>.xlsx`
- `metrics-<project>-compare-<timestamp>.xlsx`
- `codebert-dataset-<project>-<timestamp>.json`
- `codebert-dataset-<project>-<timestamp>.csv`

## Evaluasi

Evaluasi dilakukan dengan confusion matrix:

- **TP**: model memprediksi rentan dan ground truth rentan.
- **TN**: model memprediksi tidak rentan dan ground truth tidak rentan.
- **FP**: model memprediksi rentan tetapi ground truth tidak rentan.
- **FN**: model memprediksi tidak rentan tetapi ground truth rentan.

Metrik yang dihitung:

- Accuracy = (TP + TN) / (TP + TN + FP + FN)
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1-Score = 2 x Precision x Recall / (Precision + Recall)

Precision digunakan untuk melihat kemampuan sistem menekan false positive dan halusinasi. Recall digunakan untuk melihat kemampuan sistem mencegah false negative.

## Cara Menjalankan

RAG-LLM:

```powershell
dotnet run -- --mode=rag "D:\path\to\project.csproj"
```

Zero-Shot:

```powershell
dotnet run -- --mode=zero-shot "D:\path\to\project.csproj"
```

Compare RAG-LLM vs Zero-Shot:

```powershell
dotnet run -- --compare "D:\path\to\project.csproj"
```

Export dataset CodeBERT:

```powershell
dotnet run -- --mode=codebert --export-codebert-dataset "D:\path\to\project.csproj"
```

## Komponen Utama

- `Program.cs`: orkestrasi CLI, skenario inferensi, prompt Gemini, normalisasi, dan penyimpanan output.
- `CsprojPackageExtractor.cs`: parsing `.csproj`.
- `SecurityReferenceProvider.cs`: retrieval GitHub GraphQL API, local OSV DB, dan appsettings fallback.
- `GroundTruthProvider.cs`: pembentukan label ground truth dari advisory context.
- `CodeBertDatasetExporter.cs`: augmentasi dan ekspor dataset CodeBERT.
- `ModelEvaluator.cs`: perhitungan confusion matrix dan metrik evaluasi.
- `VulnerabilityModels.cs`: model data audit, dataset, ground truth, dan evaluasi.

## Ringkasan Cepat

`GeminiNuGetAuditor` membaca dependency NuGet, mengambil ground truth real-time dari GitHub GraphQL API, menjalankan skenario RAG-LLM dan Zero-Shot, menyiapkan dataset CodeBERT, lalu menghitung metrik kuantitatif untuk mengevaluasi mitigasi false positive, false negative, dan halusinasi LLM.

Last Updated: 25 Juni 2026
