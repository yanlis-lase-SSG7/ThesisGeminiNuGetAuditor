# Dokumentasi Instrumen Penelitian: NuGet Security Auditor (Gemini Pro)

## 1. Tujuan Sistem
[cite_start]Membangun aplikasi konsol .NET 8 yang berfungsi sebagai instrumen pengumpul data kuantitatif untuk mengukur akurasi Gemini Pro dalam mendeteksi kerentanan keamanan (CVE) pada dependensi NuGet[cite: 1, 13, 16].

## 2. Fungsi Utama
1. [cite_start]**Extraction**: Membaca file `.csproj` menggunakan XML parsing untuk mengambil daftar package dan versi[cite: 13, 15].
2. [cite_start]**Analysis**: Mengirimkan daftar tersebut ke Gemini Pro API dengan prompt yang meminta output JSON terstruktur[cite: 13, 15].
3. [cite_start]**Logging**: Menyimpan hasil audit ke dalam file JSON lokal sebagai dataset penelitian.

## 3. Batasan Teknis
- Target Framework: .NET 8.0.
- AI Model: Gemini Pro (via REST API).
- [cite_start]Output: Harus sesuai dengan schema `VulnerabilityReport` (PackageName, CurrentVersion, IsVulnerable, CVE_ID, Severity, MitigationPlan)[cite: 14, 16].

## 4. Metrik Keberhasilan (Research Metrics)
Data yang dihasilkan akan digunakan untuk menghitung:
- **Precision**: Akurasi temuan benar (True Positives).
- **Recall**: Kemampuan menemukan semua celah yang ada di benchmark.
- [cite_start]**F1-Score**: Keseimbangan performa deteksi[cite: 16].