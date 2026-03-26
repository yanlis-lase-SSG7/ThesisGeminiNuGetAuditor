# GeminiNuGetAuditor

`GeminiNuGetAuditor` adalah aplikasi Console berbasis `.NET 8` untuk membantu proses audit keamanan dependency NuGet pada file `.csproj`. Project ini dirancang agar user non-teknis dapat memahami status risiko package dengan cepat, sementara technician dapat menelusuri sumber data, alur proses, dan hasil analisis secara terstruktur.

## Tujuan Project

Project ini dibuat untuk menjawab kebutuhan berikut:

- menginventaris package NuGet yang digunakan oleh suatu project
- mengirim daftar package tersebut ke Gemini untuk dianalisis dari sisi keamanan
- menerima hasil analisis dalam format JSON yang terstruktur
- memetakan hasil ke model internal agar mudah ditampilkan, diproses ulang, atau diintegrasikan ke tahap berikutnya

Secara bisnis, aplikasi ini berfungsi sebagai alat bantu audit awal agar tim dapat lebih cepat mengidentifikasi package yang berpotensi rentan dan menyiapkan rencana mitigasi.

## Siapa yang Menggunakan

### 1. User
Yang dimaksud user di sini adalah developer, QA, lead engineer, atau pihak project yang ingin mengetahui apakah dependency NuGet yang dipakai mengandung risiko keamanan.

Kebutuhan user:

- tahu package apa saja yang dipakai project
- tahu package mana yang rentan
- tahu tingkat severity
- tahu referensi CVE jika tersedia
- tahu rekomendasi mitigasi atau versi aman yang sebaiknya dipertimbangkan

### 2. Technician
Technician adalah developer atau maintainer yang mengelola source code aplikasi ini.

Kebutuhan technician:

- memahami bagaimana file `.csproj` diparsing
- memahami bagaimana prompt dikirim ke Gemini
- memahami struktur JSON respons
- memahami cara aplikasi membaca API key secara aman
- memahami batasan implementasi saat ini sebelum melanjutkan pengembangan

## Business Flow Singkat

Berikut alur bisnis utama project ini:

1. User menentukan file `.csproj` yang ingin diaudit.
2. Aplikasi membaca seluruh `PackageReference` dari file tersebut.
3. Daftar package dan versinya diformat menjadi teks yang mudah dibaca model AI.
4. Aplikasi mengirim prompt audit ke Gemini Pro API.
5. Gemini diminta mengembalikan **JSON murni** yang sesuai dengan model `GeminiResponse`.
6. Aplikasi membaca hasil JSON dan mengubahnya menjadi objek C#.
7. Hasil audit disimpan ke file JSON lokal agar dapat dipakai sebagai dataset penelitian atau tindak lanjut remediation.

## Detail Alur dari Sudut Pandang User

### Langkah 1 - Menentukan target audit
User memilih project `.NET` yang dependency NuGet-nya ingin diperiksa.

### Langkah 2 - Sistem membaca dependency
Aplikasi membuka file `.csproj` dan mencari seluruh elemen `PackageReference`.

Contoh data yang diambil:

- nama package
- versi package saat ini

### Langkah 3 - Sistem meminta analisis ke Gemini
Daftar package dikirim ke Gemini dengan instruksi yang ketat agar respons berbentuk JSON yang sesuai skema internal.

### Langkah 4 - User menerima hasil audit
Setiap package akan memiliki hasil seperti:

- `PackageName`
- `CurrentVersion`
- `IsVulnerable`
- `CVE_ID`
- `Severity`
- `MitigationPlan`

Selain ditampilkan ringkas di console, hasil audit lengkap juga disimpan ke folder `audit-results` sebagai file JSON bertimestamp.

### Langkah 5 - User mengambil keputusan
Berdasarkan hasil tersebut, user dapat:

- mempertahankan versi package yang aman
- menjadwalkan upgrade package rentan
- membuat daftar remediation
- mendokumentasikan risiko untuk review keamanan

## Detail Alur dari Sudut Pandang Technician

### 1. Ekstraksi package dari `.csproj`
File `CsprojPackageExtractor.cs` menangani proses parsing XML menggunakan `System.Xml.Linq`.

Method utama:

- `ExtractPackageReferences(string filePath)`
- `ExtractPackagesFromCsproj(string filePath)`

Tanggung jawab method ini:

- memuat file `.csproj`
- mencari seluruh node `PackageReference`
- membaca atribut `Include` atau `Update` sebagai nama package
- membaca atribut `Version` atau elemen `<Version>` sebagai versi package
- menghasilkan koleksi package terstruktur untuk logging dataset
- menghasilkan string terformat untuk prompt Gemini

Jika tidak ada package, method akan mengembalikan pesan bahwa tidak ada `PackageReference` yang ditemukan.

### 2. Pengiriman request ke Gemini
File `Program.cs` berisi method:

- `AnalyzeWithGemini(string apiKey, string packageText)`
- `AnalyzeWithGemini(string packageText)`

Tanggung jawab method ini:

- menerima daftar package
- menyusun prompt audit keamanan
- menambahkan header `X-Goog-Api-Key`
- mengirim request HTTP ke endpoint Gemini
- meminta respons JSON melalui `responseMimeType = "application/json"`
- mengekstrak teks JSON dari respons Gemini
- mendeserialisasi JSON ke model `GeminiResponse`

### 3. Pembacaan API key
`Program.cs` juga memiliki method:

- `GetGeminiApiKey()`

Urutan pembacaan key:

1. `Environment.GetEnvironmentVariable("GEMINI_API_KEY")`
2. fallback ke `appsettings.local.json` pada path `Gemini:ApiKey`
3. fallback ke `appsettings.json` pada path `Gemini:ApiKey`

Dengan pendekatan ini, penggunaan environment variable menjadi prioritas utama untuk keamanan yang lebih baik.

Nilai placeholder default tidak dianggap sebagai API key valid sehingga aplikasi tidak akan melanjutkan audit jika key belum benar-benar diisi.

## Struktur Model Data

File `VulnerabilityModels.cs` mendefinisikan dua model utama.

### `VulnerabilityReport`
Mewakili hasil audit untuk satu package.

Properti:

- `PackageName`: nama package NuGet
- `CurrentVersion`: versi yang sedang dipakai
- `IsVulnerable`: status rentan atau tidak
- `CVE_ID`: referensi CVE jika tersedia
- `Severity`: tingkat keparahan
- `MitigationPlan`: saran mitigasi

### `GeminiResponse`
Root object untuk hasil respons Gemini.

Properti:

- `VulnerabilityReports`: daftar `VulnerabilityReport`

### `AuditSessionRecord`
Model ini menyimpan dataset audit lokal.

Properti utamanya:

- `GeneratedAtUtc`: waktu audit
- `SourceProjectPath`: path `.csproj` yang diperiksa
- `ModelName`: model Gemini yang dipakai
- `ExtractedPackages`: daftar package hasil ekstraksi
- `VulnerabilityReports`: hasil audit yang sudah dinormalisasi satu item per package

## Konfigurasi API Key

Project ini mendukung dua cara sederhana untuk membaca API key.

### Opsi 1 - Environment Variable
Direkomendasikan untuk penggunaan yang lebih aman.

Nama variable:

- `GEMINI_API_KEY`

Contoh PowerShell:

`$env:GEMINI_API_KEY="YOUR_NEW_KEY"`

### Opsi 2 - `appsettings.json`
Disediakan untuk local development sederhana.

Contoh isi file:

```json
{
  "Gemini": {
    "ApiKey": "YOUR_NEW_KEY"
  }
}
```

Catatan penting:

- file `appsettings.json` sudah dimasukkan ke `.gitignore`
- jangan commit API key ke repository
- jika API key pernah terekspos, lakukan revoke/regenerate

## Input dan Output

### Input utama

- path file `.csproj`
- Gemini API key

### Output utama
Output utama project ini adalah file JSON lokal berisi dataset audit lengkap (`AuditSessionRecord`) yang memuat hasil audit keamanan per package.

Contoh isi output:

- package aman atau tidak
- CVE terkait jika tersedia
- tingkat severity
- rekomendasi mitigasi

## Gambaran Arsitektur Saat Ini

Komponen utama yang sudah tersedia:

- `CsprojPackageExtractor.cs` untuk ekstraksi package
- `VulnerabilityModels.cs` untuk model hasil audit
- `Program.cs` untuk pembacaan API key dan komunikasi ke Gemini
- `appsettings.json` untuk fallback konfigurasi lokal

## Status Implementasi Saat Ini

Flow utama project kini sudah terhubung end-to-end.

Artinya:

- aplikasi menerima path `.csproj` melalui argumen atau input console
- package diekstraksi dari file target
- daftar package dikirim ke Gemini Pro API
- respons dinormalisasi agar tetap konsisten satu hasil per package
- hasil audit disimpan ke file JSON lokal pada folder `audit-results`

## Flow End-to-End yang Dituju

Flow target project ini adalah:

1. user menjalankan aplikasi
2. aplikasi menerima atau menentukan path `.csproj`
3. aplikasi memanggil `ExtractPackagesFromCsproj(...)`
4. aplikasi memanggil `AnalyzeWithGemini(...)`
5. aplikasi menerima `GeminiResponse`
6. aplikasi menormalkan hasil agar sesuai daftar package input
7. aplikasi menampilkan ringkasan dan menyimpan hasil audit sebagai dataset JSON lokal

## Cara Menjalankan

Contoh penggunaan dengan argumen:

```powershell
dotnet run -- .\ContohProject\ContohProject.csproj
```

Atau jalankan tanpa argumen lalu masukkan path `.csproj` saat diminta.

## Manfaat Bisnis

Dengan adanya project ini, tim memperoleh manfaat berikut:

- audit dependency lebih cepat
- deteksi awal risiko keamanan package
- hasil audit lebih mudah dibaca karena terstruktur
- mempermudah penyusunan rencana upgrade dan mitigasi
- mendukung proses review keamanan pada lifecycle development

## Hal yang Perlu Diperhatikan

- hasil Gemini bersifat bantuan analisis awal, bukan pengganti validasi keamanan resmi
- akurasi hasil tetap perlu diverifikasi untuk dependency yang kritikal
- koneksi internet dan API key valid diperlukan untuk analisis AI
- endpoint model AI dapat berubah mengikuti versi API provider

## Ringkasan Cepat

Jika ingin memahami project ini dalam 30 detik:

- project ini membaca package NuGet dari file `.csproj`
- daftar package dikirim ke Gemini untuk dianalisis
- Gemini diminta mengembalikan JSON sesuai model internal
- hasil audit berisi status kerentanan, CVE, severity, dan mitigation plan
- API key dibaca aman dari environment variable atau fallback `appsettings.json`

Project ini cocok sebagai fondasi tool audit dependency ringan yang dapat dikembangkan lebih lanjut menjadi tool internal tim, utility DevSecOps, atau bagian dari pipeline pemeriksaan keamanan dependency.

Last Updated : 25 Maret 2026 17:42 WIB