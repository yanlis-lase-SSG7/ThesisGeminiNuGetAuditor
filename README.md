# GeminiNuGetAuditor

`GeminiNuGetAuditor` adalah aplikasi console berbasis .NET 10 untuk audit keamanan dependency NuGet pada banyak file `.csproj` secara interaktif. Aplikasi ini menjalankan tiga alur penelitian dalam satu workflow: RAG-LLM, Zero-Shot, dan ekspor dataset CodeBERT.

## Tujuan Project

Project ini dibuat untuk:

- mengekstraksi daftar package NuGet dan versi dari file `.csproj`;
- memindai folder secara rekursif untuk menemukan banyak file `.csproj`;
- mengambil data ground truth kerentanan secara eksklusif dari GitHub GraphQL API real-time;
- menjalankan evaluasi RAG-LLM dengan Gemini dan konteks advisory;
- menjalankan evaluasi Zero-Shot dengan Gemini tanpa konteks advisory;
- menyiapkan dataset CodeBERT bridge melalui augmentasi dan split data;
- menjalankan inferensi CodeBERT lokal melalui `codebert_inference.py`, baik dengan model fine-tuned lokal maupun baseline embedding CodeBERT otomatis;
- menghitung metrik TP, TN, FP, FN, Accuracy, Precision, Recall, F1-Score, dan False Positive Ratio;
- menghasilkan artefak JSON, HTML, CSV, dan Excel untuk analisis tesis.

## Business Flow Singkat

1. User menjalankan aplikasi tanpa argumen.
2. Console meminta folder yang berisi file `.csproj`.
3. Aplikasi mencari semua `.csproj` secara rekursif dari folder tersebut.
4. Setiap project diproses secara paralel dengan checkpoint per file.
5. Untuk setiap project, aplikasi mengekstrak `PackageReference`.
6. Aplikasi menjalankan Zero-Shot dan retrieval referensi keamanan secara konkuren.
7. Setelah konteks keamanan tersedia, aplikasi membentuk ground truth, menjalankan RAG-LLM, dan menyiapkan record CodeBERT.
8. Aplikasi menjalankan Python bridge CodeBERT dan membaca file prediksi CodeBERT.
9. Hasil prediksi model dibandingkan dengan ground truth untuk menghasilkan metrik evaluasi.
10. Semua report disimpan di folder run baru di dalam `audit-results`.

## Retrieval Ground Truth

`SecurityReferenceProvider.cs` secara eksklusif menggunakan **GitHub GraphQL API sebagai sumber tunggal secara real-time** untuk mengambil advisory kerentanan NuGet. Retrieval dilakukan secara paginated agar advisory live tidak terpotong pada halaman pertama. Sistem tidak menggunakan local advisory database, fallback `appsettings.json`, dummy data, atau sumber statis lain sebagai pengganti ground truth.

Diagnostics retrieval disimpan di console log, JSON report, dan Excel report.

## Integritas Metrik

Jika Gemini API gagal total untuk sebuah skenario, aplikasi tidak akan memakai ground truth sebagai pengganti prediksi LLM. Skenario tersebut diberi status `API_FAILED`, `ExcludedFromMetrics = true`, dan tidak dimasukkan ke confusion matrix TP, TN, FP, atau FN.

Jika Python tidak tersedia sama sekali atau bootstrap dependency gagal, skenario CodeBERT diberi status `CODEBERT_FAILED`, `ExcludedFromMetrics = true`, dan tidak dimasukkan ke confusion matrix. Aplikasi membuat virtual environment lokal `.codebert-venv` dan menginstal dependency CodeBERT secara otomatis pada run pertama. Script bawaan tidak membuat prediksi sintetis. Jika `CODEBERT_MODEL_PATH` tidak diisi, script memakai baseline real lokal `LOCAL_CODEBERT_EMBEDDING_LOGREG` berbasis encoder CodeBERT dan classifier Logistic Regression dengan leave-one-package-out training untuk mengurangi package-level leakage.

Dengan kebijakan ini, metrik hanya dihitung dari prediksi model yang benar-benar berhasil dikembalikan oleh jalur inferensi masing-masing.

## Checkpoint dan Resume

Setiap scan membuat folder output baru dengan format timestamp Windows-safe, misalnya:

```text
audit-results/20261231 14-15-16/
```

Setiap hasil project disimpan sebagai JSON checkpoint di dalam folder run tersebut:

```text
audit-results/20261231 14-15-16/checkpoints/
```

Selama satu run, jika checkpoint JSON untuk sebuah `.csproj` sudah ada di folder run tersebut, project tersebut akan dilewati.

Untuk memproses ulang project tertentu di folder run yang sama, hapus file JSON checkpoint project tersebut dari folder `checkpoints`.

## Output

Output utama disimpan di folder run baru di dalam `audit-results`:

- `audit-results/20261231 14-15-16/audit-rag-llm-<timestamp>.json`
- `audit-results/20261231 14-15-16/audit-zero-shot-<timestamp>.json`
- `audit-results/20261231 14-15-16/audit-codebert-<timestamp>.json`
- `audit-results/20261231 14-15-16/audit-comprehensive-metrics-<timestamp>.csv`
- `audit-results/20261231 14-15-16/audit-comprehensive-report-<timestamp>.xlsx`
- `audit-results/20261231 14-15-16/audit-interactive-report-<timestamp>.html`
- `audit-results/20261231 14-15-16/api-diagnostics-<timestamp>.json`
- `audit-results/20261231 14-15-16/console-execution-log-<timestamp>.json`
- `audit-results/20261231 14-15-16/checkpoints/<project-key>.json`

## Cara Menjalankan

Pastikan .NET 10 SDK sudah terinstall dan konfigurasi API tersedia melalui environment variable atau `appsettings.json`.

Environment variable yang umum digunakan:

```powershell
$env:GEMINI_API_KEY = "your-gemini-api-key"
$env:GITHUB_TOKEN = "your-github-token"
```

Jalankan aplikasi tanpa argumen:

```powershell
dotnet run
```

Console akan meminta input:

```text
Please enter the folder path containing the .csproj files to audit:
```

Masukkan folder root yang berisi project `.NET`, misalnya:

```text
D:\path\to\solution-or-project-folder
```

Aplikasi akan mencari semua file `.csproj` di folder tersebut secara rekursif, lalu menjalankan RAG-LLM, Zero-Shot, dan CodeBERT Python bridge secara paralel dengan checkpoint otomatis. Pada run pertama, aplikasi membuat `.codebert-venv` dan menginstal dependency CodeBERT otomatis. Jika `CODEBERT_MODEL_PATH` tidak diisi, CodeBERT memakai baseline embedding lokal otomatis dengan leave-one-package-out; jika Python atau bootstrap dependency gagal, jalur CodeBERT gagal dengan aman dan tidak dihitung sebagai metrik model.

## Komponen Utama

- `Program.cs`: orkestrasi interactive directory scan, parallel processing, checkpointing, Gemini inference, evaluasi, dan penyimpanan report.
- `CsprojPackageExtractor.cs`: parsing `.csproj` dan ekstraksi `PackageReference`.
- `SecurityReferenceProvider.cs`: retrieval GitHub GraphQL API sebagai satu-satunya sumber ground truth real-time.
- `GroundTruthProvider.cs`: pembentukan label ground truth dari advisory context.
- `CodeBertDatasetExporter.cs`: augmentasi dan ekspor dataset CodeBERT.
- `codebert_inference.py`: bridge inferensi CodeBERT lokal berbasis HuggingFace `transformers`.
- `ModelEvaluator.cs`: perhitungan confusion matrix dan metrik evaluasi.
- `VulnerabilityModels.cs`: model data audit, dataset, ground truth, dan evaluasi.

## Ringkasan Cepat

`GeminiNuGetAuditor` memindai folder berisi banyak `.csproj`, mengekstrak dependency NuGet, mengambil ground truth keamanan, menjalankan RAG-LLM dan Zero-Shot dengan Gemini, menjalankan CodeBERT lokal secara otomatis, lalu menghasilkan JSON, HTML, CSV, dan Excel report untuk evaluasi penelitian.

Last Updated: 27 Juni 2026
