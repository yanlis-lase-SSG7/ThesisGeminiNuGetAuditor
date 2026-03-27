# Dokumentasi Instrumen Penelitian: RAG-Based NuGet Security Auditor

## 1. Tujuan Sistem
[cite_start]Membangun instrumen penelitian kuantitatif berbasis .NET 8 untuk menguji akurasi deteksi kerentanan NuGet menggunakan arsitektur Retrieval-Augmented Generation (RAG)[cite: 92, 98].

## 2. Arsitektur Solusi (Hulu ke Hilir)
1. [cite_start]**Extraction**: Membaca file `.csproj` untuk mengambil daftar `PackageReference`[cite: 78].
2. [cite_start]**Retrieval (The RAG Part)**: Sistem harus mencari referensi data keamanan nyata (seperti GitHub Advisory Database atau NIST) sebagai "Ground Truth" untuk membatasi halusinasi AI[cite: 38, 40].
3. [cite_start]**Augmentation**: Menggabungkan daftar package dari user dengan data referensi keamanan ke dalam satu prompt terstruktur[cite: 39].
4. [cite_start]**Generation**: Gemini Pro melakukan reasoning untuk menentukan apakah package tersebut benar-benar berisiko dalam konteks .NET 8/9[cite: 96].

## 3. Spesifikasi Teknis
- [cite_start]**Target Framework**: .NET 8.0[cite: 66].
- [cite_start]**AI Model**: Gemini Pro (Long-context reasoning enabled)[cite: 36].
- [cite_start]**Anti-Hallucination Guardrail**: Prompt harus memaksa model untuk menjawab "Unknown" jika data tidak ditemukan di referensi eksternal[cite: 40].

## 4. Metrik Penelitian (Performance Metrics)
Data output harus memungkinkan penghitungan statistik:
- [cite_start]**Precision**: Rasio temuan celah keamanan yang benar-benar valid[cite: 9, 81].
- [cite_start]**Recall**: Kemampuan sistem menemukan seluruh celah yang terdaftar di database resmi[cite: 9, 81].
- [cite_start]**F1-Score**: Keseimbangan antara akurasi dan jangkauan deteksi[cite: 8, 100].