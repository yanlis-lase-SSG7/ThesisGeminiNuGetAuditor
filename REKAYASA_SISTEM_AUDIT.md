# Rekayasa Sistem Audit Keamanan NuGet Berbasis RAG-LLM

## 1. Pendahuluan

Dokumen ini menjelaskan rancangan teknis `GeminiNuGetAuditor` sebagai instrumen penelitian untuk mendeteksi kerentanan dependency NuGet pada ekosistem .NET. Rancangan sistem diselaraskan dengan metodologi tesis Bab III, yaitu pendekatan eksperimental komparatif yang mengevaluasi efektivitas Retrieval-Augmented Generation berbasis Large Language Model terhadap skenario Zero-Shot dan baseline deep learning CodeBERT.

Tujuan utama sistem adalah menyediakan pipeline yang replikatif untuk:

- mengekstraksi dependency dari file `.csproj`;
- mengambil ground truth kerentanan dari sumber advisory yang tervalidasi;
- menjalankan inferensi pada beberapa skenario evaluasi;
- menyiapkan dataset pembanding untuk CodeBERT;
- menghitung metrik kuantitatif berbasis confusion matrix.

## 2. Kerangka Arsitektur Sistem

Secara konseptual, sistem terdiri atas lima tahap utama:

1. **Extraction**  
   Sistem membaca file `.csproj` dan mengekstraksi elemen `PackageReference`, meliputi nama package dan versi yang digunakan.

2. **Retrieval**  
   Sistem mengambil referensi keamanan sebagai ground truth. Urutan retrieval adalah:
   - Priority 1: GitHub GraphQL API sebagai sumber real-time;
   - Fallback 1: local OSV/GitHub Advisory database melalui `github-advisory-db.json`;
   - Fallback 2: sample advisories pada `appsettings.json`.

3. **Ground Truth Labeling**  
   Data advisory yang diperoleh dipetakan ke dependency hasil ekstraksi untuk menghasilkan label `Vulnerable` atau `Not Vulnerable`.

4. **Inference and Dataset Preparation**  
   Sistem menjalankan skenario RAG-LLM dan Zero-Shot menggunakan Gemini 1.5 Pro, serta mengekspor dataset baseline CodeBERT.

5. **Evaluation**  
   Hasil prediksi dibandingkan terhadap ground truth untuk menghitung TP, TN, FP, FN, Accuracy, Precision, Recall, dan F1-Score.

## 3. Pengumpulan Data dan Ground Truth

Pengumpulan data dilakukan terhadap file proyek `.csproj` dari ekosistem .NET. Setiap dependency NuGet yang ditemukan diperlakukan sebagai unit observasi. Label kerentanan tidak ditentukan secara manual, tetapi dibangun dari metadata advisory yang tervalidasi.

Sumber ground truth mengikuti prioritas berikut:

1. **GitHub GraphQL API**  
   Sumber utama karena menyediakan akses real-time ke GitHub Advisory Database. Sistem memanggil query GraphQL untuk package NuGet yang dianalisis.

2. **Local OSV/GitHub Advisory Database**  
   Digunakan ketika GitHub API gagal karena timeout, rate-limit, HTTP error, token tidak valid, atau respons tidak dapat diparse. File lokal yang digunakan adalah `github-advisory-db.json`.

3. **Appsettings Fallback**  
   Digunakan ketika file lokal tidak tersedia atau rusak. Fallback ini berasal dari konfigurasi `SecurityReference:FallbackAdvisories`.

Strategi berlapis ini menjaga validitas data sekaligus memastikan sistem tetap dapat berjalan pada kondisi jaringan tidak stabil.

## 4. Skenario Evaluasi

Penelitian menggunakan tiga skenario utama untuk memastikan perbandingan yang adil.

### 4.1. Skenario RAG-LLM (Model Usulan)

Skenario RAG-LLM menggunakan Gemini 1.5 Pro dengan konteks tambahan berupa data advisory. Mekanisme retrieval dilakukan sebelum prompt dikirim ke LLM. Prompt berisi daftar dependency lokal dan security reference data.

Kriteria perilaku model pada skenario ini:

- model hanya boleh menandai package sebagai rentan jika didukung data advisory;
- `IsGroundedInReference` bernilai `true` hanya jika temuan berasal dari referensi;
- package yang tidak ditemukan pada referensi ditandai sebagai tidak rentan atau tidak diketahui, bukan direka sebagai temuan baru.

Skenario ini dirancang untuk mengurangi halusinasi dan false positive.

### 4.2. Skenario Zero-Shot

Skenario Zero-Shot menggunakan Gemini 1.5 Pro tanpa injeksi konteks retrieval. Model hanya menerima daftar package dan versi, lalu diminta melakukan audit berdasarkan pengetahuan internalnya.

Skenario ini berfungsi sebagai pembanding untuk mengukur:

- kecenderungan halusinasi;
- false positive;
- risiko rekomendasi package atau advisory yang tidak tervalidasi;
- potensi Slopsquatting ketika model menghasilkan klaim keamanan tanpa ground truth.

Pada skenario ini, `IsGroundedInReference` harus bernilai `false` karena tidak ada referensi eksternal yang diberikan ke model.

### 4.3. Skenario CodeBERT (Deep Learning Baseline)

Skenario CodeBERT digunakan sebagai baseline deep learning statis. CodeBERT tidak menggunakan retrieval saat inferensi. Dataset untuk skenario ini disiapkan oleh `CodeBertDatasetExporter`.

Dataset memuat:

- nama package asli;
- versi package;
- snippet `.csproj`;
- label ground truth;
- metadata advisory seperti CVE, severity, dan advisory ID;
- variasi augmentasi.

Skenario ini digunakan untuk membandingkan pendekatan RAG-LLM dengan model deep learning yang dilatih pada data historis.

## 5. Augmentasi Data dan Strategi Split

`CodeBertDatasetExporter` menyiapkan dataset untuk baseline CodeBERT melalui augmentasi yang mempertahankan semantik. Strategi augmentasi meliputi:

- **original**: representasi dependency sebagaimana ditemukan pada `.csproj`;
- **semantic_version_normalization**: perubahan bentuk struktur XML versi, misalnya dari atribut menjadi elemen `<Version>`;
- **safe_dummy_dependency**: penyisipan dependency dummy aman untuk menambah sampel negatif.

Setelah augmentasi, dataset dibagi menjadi:

- **70% training** untuk pelatihan model;
- **15% validation** untuk validasi selama fine-tuning;
- **15% testing** untuk evaluasi akhir.

Pembagian dilakukan secara deterministik agar eksperimen dapat direplikasi.

## 6. Model Output dan Bilingual Reporting

Output inferensi LLM dipaksa berbentuk JSON yang sesuai dengan model `GeminiResponse`. Setiap item `VulnerabilityReport` memuat:

- `PackageName`;
- `CurrentVersion`;
- `IsVulnerable`;
- `CVE_ID`;
- `Severity`;
- `SeverityIndonesia`;
- `MitigationPlan`;
- `MitigationPlanIndonesia`;
- `IsGroundedInReference`;
- `ReasoningTrace`;
- `ReasoningTraceIndonesia`.

Field bilingual digunakan agar hasil audit dapat dipahami dalam konteks teknis internasional dan konteks akademik Indonesia.

## 7. Metrik Evaluasi

Evaluasi dilakukan dengan membandingkan prediksi model terhadap ground truth. Empat nilai dasar confusion matrix adalah:

- **True Positive (TP)**: model memprediksi rentan dan ground truth memang rentan.
- **True Negative (TN)**: model memprediksi tidak rentan dan ground truth memang tidak rentan.
- **False Positive (FP)**: model memprediksi rentan, tetapi ground truth tidak rentan.
- **False Negative (FN)**: model memprediksi tidak rentan, tetapi ground truth rentan.

Rumus metrik yang digunakan:

```text
Accuracy = (TP + TN) / (TP + TN + FP + FN)
```

```text
Precision = TP / (TP + FP)
```

```text
Recall = TP / (TP + FN)
```

```text
F1-Score = 2 x Precision x Recall / (Precision + Recall)
```

Precision menjadi indikator utama untuk menilai mitigasi false positive dan halusinasi. Recall digunakan untuk menilai kemampuan model menemukan kerentanan aktual dan mencegah false negative. F1-Score digunakan sebagai ukuran harmonik ketika distribusi data rentan dan tidak rentan tidak seimbang.

## 8. Kriteria Keberhasilan

Arsitektur RAG-LLM dinilai efektif apabila menunjukkan peningkatan dibanding Zero-Shot dan CodeBERT, terutama pada:

- peningkatan **Precision**, yang menunjukkan penurunan false positive dan halusinasi;
- peningkatan atau stabilitas **Recall**, yang menunjukkan kemampuan menemukan kerentanan aktual;
- peningkatan **F1-Score**, yang menunjukkan keseimbangan antara Precision dan Recall.

Dengan demikian, keberhasilan sistem tidak hanya diukur dari banyaknya temuan, tetapi dari kemampuan menghasilkan temuan yang akurat dan dapat ditelusuri ke ground truth.

## 9. Artefak Sistem

Artefak yang dihasilkan oleh sistem meliputi:

- file audit JSON untuk setiap skenario LLM;
- file Excel metrik evaluasi;
- dataset CodeBERT dalam format JSON dan CSV;
- diagnostics console yang mencatat sumber retrieval yang digunakan.

Artefak ini mendukung kebutuhan replikasi, audit metodologis, dan pelaporan hasil penelitian.

## 10. Kesimpulan Rekayasa

`GeminiNuGetAuditor` direkayasa sebagai instrumen penelitian yang menggabungkan parsing dependency .NET, retrieval data advisory real-time, inferensi LLM, baseline deep learning, dan evaluasi kuantitatif. Struktur ini memungkinkan pengujian empiris terhadap hipotesis bahwa RAG-LLM mampu mengurangi halusinasi dan meningkatkan kualitas deteksi kerentanan dibandingkan Zero-Shot dan CodeBERT.
