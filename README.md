# GeminiNuGetAuditor

`GeminiNuGetAuditor` adalah aplikasi Console berbasis `.NET 8` untuk audit keamanan dependency NuGet pada file `.csproj` dengan pendekatan **Retrieval-Augmented Generation (RAG)**.

## Tujuan Project

Project ini dibuat untuk:

- menginventaris package NuGet yang digunakan oleh suatu project
- mengambil **security reference data** lokal (`github-advisory-db.json`) sebagai ground truth
- mengirim package + konteks referensi ke Gemini untuk analisis terarah
- menurunkan risiko halusinasi dengan aturan "Unknown jika tidak ada di referensi"
- menyimpan hasil audit ke JSON dan CSV untuk analisis kuantitatif (Precision, Recall, F1-Score)

## Business Flow Singkat

Berikut alur bisnis utama project ini:

1. User menentukan file `.csproj` yang ingin diaudit.
2. Aplikasi membaca seluruh `PackageReference` dari file tersebut (Extraction).
3. Aplikasi mengambil context referensi keamanan dari `github-advisory-db.json` (Retrieval).
4. Daftar package + referensi keamanan digabung dalam prompt (Augmentation).
5. Gemini diminta mengembalikan **JSON murni** sesuai model `GeminiResponse` (Generation).
6. Hasil dinormalisasi agar 1 package = 1 report.
7. Aplikasi menyimpan:
   - dataset audit `.json`
   - dataset metrik `.csv` untuk evaluasi klasifikasi

## Detail Alur dari Sudut Pandang User

### Langkah 1 - Menentukan target audit
User memilih project `.NET` yang dependency NuGet-nya ingin diperiksa.

### Langkah 2 - Sistem membaca dependency
Aplikasi membuka file `.csproj` dan mencari seluruh elemen `PackageReference`.

Contoh data yang diambil:

- nama package
- versi package saat ini

### Langkah 3 - Sistem mengambil referensi keamanan (Ground Truth)
Aplikasi membaca `github-advisory-db.json`, lalu memfilter advisory yang cocok dengan package lokal.

### Langkah 4 - Sistem meminta analisis ke Gemini
Gemini menerima package lokal + security context dengan aturan:

- hanya tandai rentan jika ada pada referensi
- jika package tidak ada pada referensi, status harus Unknown
- mitigation plan mengikuti standar keamanan `.NET 8/9`

### Langkah 5 - User menerima hasil audit
Setiap package memiliki hasil seperti:

- `PackageName`
- `CurrentVersion`
- `IsVulnerable`
- `CVE_ID`
- `Severity`
- `MitigationPlan`
- `IsGroundedInReference`
- `ReasoningTrace`

### Langkah 6 - Dataset penelitian tersimpan
Hasil audit disimpan ke folder `audit-results` dalam dua format:

- JSON audit lengkap per sesi
- CSV metrik klasifikasi per package

## Detail Alur dari Sudut Pandang Technician

### 1. Ekstraksi package dari `.csproj`
File `CsprojPackageExtractor.cs` menangani parsing XML menggunakan `System.Xml.Linq`.

Method utama:

- `ExtractPackageReferences(string filePath)`
- `ExtractPackagesFromCsproj(string filePath)`

### 2. Retrieval security reference
File `SecurityReferenceProvider.cs` menangani pembacaan database advisory lokal.

Method utama:

- `GetSecurityContext(List<string> packages)`

Tanggung jawab method ini:

- membaca file `github-advisory-db.json`
- mengekstrak daftar advisory (beberapa bentuk struktur JSON didukung)
- memfilter advisory berdasarkan nama package dari `.csproj`
- mengembalikan context JSON terfilter untuk prompt RAG

### 3. Pengiriman request ke Gemini
File `Program.cs` berisi method:

- `AnalyzeWithGemini(string apiKey, string modelName, IReadOnlyCollection<NuGetPackageReference> packageReferences, string securityContext)`
- `AnalyzeWithGemini(IReadOnlyCollection<NuGetPackageReference> packageReferences, string securityContext)`

Tanggung jawab method ini:

- menerima package lokal dan context referensi keamanan
- menyusun prompt RAG anti-halusinasi
- menambahkan header `X-Goog-Api-Key`
- mengirim request HTTP ke endpoint Gemini
- mengekstrak payload JSON dari respons Gemini
- mendeserialisasi ke model `GeminiResponse`

### 4. Logging dataset JSON dan CSV
Setelah normalisasi, aplikasi menyimpan:

- JSON sesi audit (`AuditSessionRecord`)
- CSV metrik klasifikasi (`SaveScanMetricsCsv(...)`) dengan kolom:
  - `ProjectName`
  - `PackageName`
  - `Gemini_Detected`
  - `Reference_Exists`
  - `Match_Result` (`True Positive`, `False Positive`, `False Negative`, `True Negative`)

## Struktur Model Data

File `VulnerabilityModels.cs` mendefinisikan model utama berikut.

### `VulnerabilityReport`
Mewakili hasil audit untuk satu package.

Properti:

- `PackageName`
- `CurrentVersion`
- `IsVulnerable`
- `CVE_ID`
- `Severity`
- `MitigationPlan`
- `IsGroundedInReference`
- `ReasoningTrace`

### `GeminiResponse`
Root object respons Gemini:

- `VulnerabilityReports`

### `AuditSessionRecord`
Dataset audit per sesi:

- `GeneratedAtUtc`
- `SourceProjectPath`
- `ModelName`
- `ExtractedPackages`
- `VulnerabilityReports`

## Input dan Output

### Input utama

- path file `.csproj`
- Gemini API key
- file referensi lokal `github-advisory-db.json`

### Output utama

- file JSON lokal berisi dataset audit lengkap (`AuditSessionRecord`)
- file CSV metrik klasifikasi per package untuk analisis Precision, Recall, dan F1-Score

### Format CSV Metrik

File CSV berisi kolom berikut:

- `ProjectName`: nama project sumber (`.csproj`)
- `PackageName`: nama package yang dievaluasi
- `Gemini_Detected`: hasil prediksi model (`true/false`)
- `Reference_Exists`: status keberadaan package pada referensi keamanan (`true/false`)
- `Match_Result`: label evaluasi klasifikasi

Nilai `Match_Result`:

- `True Positive (TP)`: `Gemini_Detected=true` dan `Reference_Exists=true`
- `False Positive (FP)`: `Gemini_Detected=true` dan `Reference_Exists=false`
- `False Negative (FN)`: `Gemini_Detected=false` dan `Reference_Exists=true`
- `True Negative (TN)`: `Gemini_Detected=false` dan `Reference_Exists=false`

Contoh baris CSV:

`MyProject,Newtonsoft.Json,true,true,True Positive`

## Metrik Penelitian Kuantitatif

Dataset CSV dapat langsung dipakai untuk menghitung metrik utama:

- `Precision = TP / (TP + FP)`
- `Recall = TP / (TP + FN)`
- `F1-Score = 2 * (Precision * Recall) / (Precision + Recall)`

Interpretasi singkat:

- Precision tinggi: false alarm rendah
- Recall tinggi: temuan rentan yang terdeteksi lebih lengkap
- F1 tinggi: keseimbangan akurasi deteksi dan jangkauan temuan

## Asumsi Evaluasi

Agar hasil konsisten untuk eksperimen tesis:

- ground truth berasal dari `github-advisory-db.json` yang dipakai pada proses retrieval
- package yang tidak ditemukan pada referensi diperlakukan sebagai `Unknown` oleh prompt
- evaluasi klasifikasi tetap menggunakan pasangan biner (`Gemini_Detected` vs `Reference_Exists`) untuk perhitungan TP/FP/FN/TN
- setiap scan menghasilkan file CSV baru bertimestamp untuk menjaga jejak eksperimen

## Gambaran Arsitektur Saat Ini

Komponen utama:

- `CsprojPackageExtractor.cs` untuk extraction
- `SecurityReferenceProvider.cs` untuk retrieval context
- `Program.cs` untuk augmentation + generation + normalisasi + persistence
- `VulnerabilityModels.cs` untuk model hasil audit

## Flow End-to-End yang Dituju

1. aplikasi menerima/menentukan path `.csproj`
2. aplikasi melakukan extraction package
3. aplikasi memanggil `GetSecurityContext(...)` untuk retrieval
4. aplikasi memanggil `AnalyzeWithGemini(...)` dengan package + security context
5. aplikasi menerima `GeminiResponse`
6. aplikasi menormalkan hasil agar sesuai daftar package input
7. aplikasi menyimpan JSON audit dan CSV metrik

## Ringkasan Cepat

Jika ingin memahami project ini dalam 30 detik:

- project membaca package NuGet dari `.csproj`
- project mengambil ground truth dari `github-advisory-db.json`
- package + referensi dikirim ke Gemini (RAG prompt)
- hasil audit menyertakan status kerentanan, grounding reference, dan reasoning trace
- output disimpan ke JSON dan CSV agar bisa dihitung metrik Precision/Recall/F1

Last Updated : 27 Maret 2026