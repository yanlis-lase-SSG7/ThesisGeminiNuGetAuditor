# GeminiNuGetAuditor

`GeminiNuGetAuditor` adalah aplikasi Console berbasis `.NET 10` untuk audit keamanan dependency NuGet pada file `.csproj` dengan pendekatan **Retrieval-Augmented Generation (RAG)**.

## Tujuan Project

Project ini dibuat untuk:

- menginventaris package NuGet yang digunakan oleh suatu project
- mengambil **security reference data** sebagai ground truth dari beberapa sumber (local file, GitHub GraphQL API, fallback sample)
- mengirim package + konteks referensi ke Gemini untuk analisis terarah
- menurunkan risiko halusinasi dengan aturan "Unknown jika tidak ada di referensi"
- menyimpan hasil audit ke JSON dan Excel untuk analisis kuantitatif (Accuracy, Precision, Recall, F1-Score)

## Business Flow Singkat

Berikut alur bisnis utama project ini:

1. User menentukan file `.csproj` yang ingin diaudit.
2. Aplikasi membaca seluruh `PackageReference` dari file tersebut (Extraction).
3. Aplikasi mengambil context referensi keamanan dengan prioritas:
   - local file `github-advisory-db.json`
   - GitHub GraphQL API
   - fallback advisory sample di `appsettings` (Retrieval).
4. Daftar package + referensi keamanan digabung dalam prompt (Augmentation).
5. Gemini diminta mengembalikan **JSON murni** sesuai model `GeminiResponse` (Generation).
6. Hasil dinormalisasi agar 1 package = 1 report.
7. Aplikasi menyimpan:
   - dataset audit `.json`
   - dataset metrik `.xlsx` (Summary, Detail, Summary Details)
   - untuk mode compare: workbook komparasi `RAG vs Non-RAG`

## Detail Alur dari Sudut Pandang User

### Langkah 3 - Sistem mengambil referensi keamanan (Ground Truth)
Aplikasi melakukan retrieval berlapis:

1. baca `github-advisory-db.json` jika tersedia
2. jika tidak tersedia, query GitHub GraphQL API
3. jika API gagal/tidak tersedia, gunakan fallback advisories dari `appsettings`

Setiap proses retrieval menampilkan diagnostics di console agar sumber data dapat diverifikasi.

### Langkah 5 - User menerima hasil audit
Setiap package memiliki hasil seperti:

- `PackageName`
- `CurrentVersion`
- `IsVulnerable`
- `CVE_ID`
- `Severity` (EN)
- `SeverityIndonesia` (ID)
- `MitigationPlan` (EN)
- `MitigationPlanIndonesia` (ID)
- `IsGroundedInReference`
- `ReasoningTrace` (EN)
- `ReasoningTraceIndonesia` (ID)

`AuditSessionRecord` juga menyertakan `VulnerabilityReportFieldDescriptions` yang berisi deskripsi field dan arti value (khusus field kategorikal/boolean).

## Detail Alur dari Sudut Pandang Technician

### 2. Retrieval security reference
File `SecurityReferenceProvider.cs` menangani retrieval context dari beberapa sumber.

Method utama:

- `GetSecurityContext(List<string> packages)`
- `GetSecurityContextWithDiagnostics(List<string> packages)`

Tanggung jawab method ini:

- mencoba local advisory file terlebih dahulu
- fallback ke GitHub GraphQL API jika local file tidak ada
- fallback ke sample advisories jika API gagal/tidak tersedia
- mengembalikan diagnostics detail source retrieval untuk logging console

### 3. Pengiriman request ke Gemini
`Program.cs` menampilkan diagnostics request Gemini di console, termasuk:

- endpoint yang dipanggil
- HTTP status response
- status parsing payload

Tujuannya agar mudah memverifikasi bahwa request benar-benar mengakses API Gemini, bukan gagal diam-diam.

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
- `SeverityIndonesia`
- `MitigationPlan`
- `MitigationPlanIndonesia`
- `IsGroundedInReference`
- `ReasoningTrace`
- `ReasoningTraceIndonesia`

## Input dan Output

### Input utama

- path file `.csproj`
- Gemini API key (`GEMINI_API_KEY` atau `Gemini:ApiKey`)
- GitHub token (`GITHUB_TOKEN` atau `SecurityReference:GitHubToken`)
- konfigurasi retrieval pada section `SecurityReference` di `appsettings`

### Output utama

- file JSON lokal berisi dataset audit lengkap (`AuditSessionRecord`)
- file Excel metrik klasifikasi per package untuk analisis Accuracy, Precision, Recall, dan F1-Score
- diagnostics detail di console untuk status retrieval source dan status akses Gemini API

### Output mode compare (`--compare`)

- `audit-<project>-rag-<timestamp>.json`
- `audit-<project>-nonrag-<timestamp>.json`
- `metrics-<project>-compare-<timestamp>.xlsx`

Workbook compare berisi sheet `Model Comparison` dengan kriteria penelitian:

- `Precision(RAG) > Precision(Non-RAG)`
- `FP Ratio(RAG) < FP Ratio(Non-RAG)`

Catatan interpretasi:
- Status `FAIL` berarti **minimal satu** kriteria di atas tidak terpenuhi pada run tersebut.
- Jika Non-RAG tidak menghasilkan prediksi positif sama sekali (`TP+FP = 0`), maka `FP Ratio Non-RAG = 0`; pada kondisi ini, sangat sulit bagi RAG untuk memenuhi syarat `FP Ratio(RAG) < FP Ratio(Non-RAG)` kecuali desain evaluasi baseline disesuaikan.

## Gambaran Arsitektur Saat Ini

Komponen utama:

- `CsprojPackageExtractor.cs` untuk extraction
- `SecurityReferenceProvider.cs` untuk retrieval context + diagnostics
- `Program.cs` untuk augmentation + generation + normalisasi + persistence
- `VulnerabilityModels.cs` untuk model hasil audit (bilingual fields)

## Ringkasan Cepat

Jika ingin memahami project ini dalam 30 detik:

- project membaca package NuGet dari `.csproj`
- project mengambil ground truth dari local file/GitHub API/fallback sample
- package + referensi dikirim ke Gemini (RAG prompt)
- hasil audit menyertakan field bilingual EN-ID untuk severity, mitigation, dan reasoning
- output disimpan ke JSON + Excel, dan console menampilkan diagnostics akses API

## Cara Menjalankan

- Non-RAG:
  - `GeminiNuGetAuditor.exe --mode=nonrag "D:\Project S2\yanlis-lase-SSG7\ThesisGeminiNuGetAuditor\samples\DummyAuditTarget\DummyAuditTarget.csproj"`
- RAG:
  - `GeminiNuGetAuditor.exe --mode=rag "D:\Project S2\yanlis-lase-SSG7\ThesisGeminiNuGetAuditor\samples\DummyAuditTarget\DummyAuditTarget.csproj"`
- Compare:
  - `GeminiNuGetAuditor.exe --compare "D:\Project S2\yanlis-lase-SSG7\ThesisGeminiNuGetAuditor\samples\DummyAuditTarget\DummyAuditTarget.csproj"`

Tips saat debugging di Visual Studio:
- isi argumen di **Debug > Command line arguments**
- saat prompt `Masukkan path file .csproj...`, masukkan **path saja** bila argumen tidak dikirim dari profile debug

Last Updated : 05 Mei 2026