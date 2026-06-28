# Rekayasa Sistem Audit Keamanan NuGet Berbasis RAG-LLM

## 1. Pendahuluan

Dokumen ini menjelaskan rancangan teknis `GeminiNuGetAuditor` sebagai instrumen penelitian untuk mendeteksi kerentanan dependency NuGet pada ekosistem .NET. Rancangan sistem diselaraskan dengan metodologi tesis Bab III, yaitu pendekatan eksperimental komparatif yang mengevaluasi efektivitas Retrieval-Augmented Generation berbasis Large Language Model terhadap skenario Zero-Shot dan skenario CodeBERT Python bridge sebagai validasi pipeline.

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
   Sistem mengambil referensi keamanan sebagai ground truth secara eksklusif dari GitHub GraphQL API real-time. Tidak ada fallback ke file lokal, appsettings, dummy data, atau sumber statis lain.

3. **Ground Truth Labeling**  
   Data advisory yang diperoleh dipetakan ke dependency hasil ekstraksi untuk menghasilkan label `Vulnerable` atau `Not Vulnerable`.

4. **Inference and Dataset Preparation**  
   Sistem menjalankan skenario RAG-LLM dan Zero-Shot menggunakan Gemini Pro melalui Vertex AI, serta mengekspor dataset dan menjalankan Python bridge untuk skenario CodeBERT.

5. **Evaluation**  
   Hasil prediksi dibandingkan terhadap ground truth untuk menghitung TP, TN, FP, FN, Accuracy, Precision, Recall, dan F1-Score.

## 3. Pengumpulan Data dan Ground Truth

Pengumpulan data dilakukan terhadap file proyek `.csproj` dari ekosistem .NET. Setiap dependency NuGet yang ditemukan diperlakukan sebagai unit observasi. Label kerentanan tidak ditentukan secara manual, tetapi dibangun dari metadata advisory yang tervalidasi.

Sumber ground truth adalah **GitHub GraphQL API sebagai sumber tunggal secara real-time**. Sistem memanggil query GraphQL secara paginated untuk setiap package NuGet yang dianalisis agar advisory live tidak terpotong pada halaman pertama. Hasil advisory live tersebut kemudian dipakai untuk mengevaluasi apakah `CurrentVersion` berada di dalam `vulnerableVersionRange`.

Untuk menjaga integritas eksperimen, sistem tidak menggunakan fallback ke `github-advisory-db.json`, appsettings, dummy data, cache statis, atau sumber lokal lain. Jika GitHub GraphQL API gagal karena timeout, rate-limit, HTTP error, token tidak valid, atau respons tidak dapat diparse, project ditandai `RETRIEVAL_FAILED` dan seluruh skenario pada project tersebut dikeluarkan dari perhitungan confusion matrix. Dengan demikian, metrik Bab IV hanya berasal dari project yang memiliki ground truth live yang berhasil diambil.

## 4. Skenario Evaluasi

Penelitian menggunakan tiga skenario utama untuk memastikan perbandingan yang adil.

### 4.1. Skenario RAG-LLM (Model Usulan)

Skenario RAG-LLM menggunakan Gemini Pro melalui Vertex AI dengan konteks tambahan berupa data advisory live dari GitHub GraphQL API. Mekanisme retrieval dilakukan sebelum prompt dikirim ke LLM. Prompt berisi daftar dependency lokal dan security reference data yang berhasil diambil secara real-time.

Kriteria perilaku model pada skenario ini:

- model hanya boleh menandai package sebagai rentan jika didukung data advisory;
- `IsGroundedInReference` bernilai `true` hanya jika temuan berasal dari referensi;
- package yang tidak ditemukan pada referensi ditandai sebagai tidak rentan atau tidak diketahui, bukan direka sebagai temuan baru.

Skenario ini dirancang untuk mengurangi halusinasi dan false positive.

### 4.2. Skenario Zero-Shot

Skenario Zero-Shot menggunakan Gemini Pro melalui Vertex AI tanpa injeksi konteks retrieval. Model hanya menerima daftar package dan versi, lalu diminta melakukan audit berdasarkan pengetahuan internalnya.

Skenario ini berfungsi sebagai pembanding untuk mengukur:

- kecenderungan halusinasi;
- false positive;
- risiko rekomendasi package atau advisory yang tidak tervalidasi;
- potensi Slopsquatting ketika model menghasilkan klaim keamanan tanpa ground truth.

Pada skenario ini, `IsGroundedInReference` harus bernilai `false` karena tidak ada referensi eksternal yang diberikan ke model.

### 4.3. Skenario CodeBERT (Deep Learning Baseline)

Skenario CodeBERT digunakan sebagai Python inference bridge untuk memvalidasi pipeline ekspor dataset, eksekusi lokal, pembacaan prediksi, dan perhitungan metrik terpadu. Implementasi saat ini bersifat real-only: `Scripts/CodeBert/codebert_inference.py` tidak menghasilkan prediksi sintetis. Jika tersedia model sequence-classification fine-tuned lokal melalui `CODEBERT_MODEL_PATH` atau argumen `--model`, sistem memakai model tersebut. Jika tidak, sistem menjalankan baseline lokal `LOCAL_CODEBERT_EMBEDDING_LOGREG`, yaitu encoder CodeBERT untuk ekstraksi embedding dan Logistic Regression dengan mekanisme leave-one-package-out agar classifier tidak dilatih dari package yang sedang diprediksi. Untuk efisiensi, inferensi CodeBERT dijalankan dalam batch satu proses Python sehingga encoder dimuat sekali untuk banyak project; script juga memakai CUDA secara otomatis jika PyTorch mendeteksi GPU.

Dataset memuat:

- nama package asli;
- versi package;
- snippet `.csproj`;
- label ground truth;
- metadata advisory seperti CVE, severity, dan advisory ID;
- variasi augmentasi.

Pada run pertama, aplikasi membuat virtual environment lokal `.codebert-venv` dan menginstal dependency dari `Scripts/CodeBert/requirements-codebert.txt` secara otomatis. Jika Python tidak tersedia atau bootstrap dependency gagal, skenario CodeBERT ditandai `CODEBERT_FAILED`, dikeluarkan dari confusion matrix, dan tidak menghasilkan metrik model. Dengan demikian, eksperimen final tidak mencampurkan hasil RAG-LLM/Zero-Shot real dengan prediksi CodeBERT palsu.

## 5. Augmentasi Data dan Strategi Split

`CodeBertDatasetExporter` menyiapkan dataset untuk skenario CodeBERT bridge melalui augmentasi yang mempertahankan semantik. Strategi augmentasi meliputi:

- **original**: representasi dependency sebagaimana ditemukan pada `.csproj`;
- **semantic_version_normalization**: perubahan bentuk struktur XML versi, misalnya dari atribut menjadi elemen `<Version>`;
- **safe_dummy_dependency**: penyisipan dependency dummy aman untuk menambah sampel negatif.

Setelah augmentasi, record dataset dibagi menjadi:

- **70% training** sebagai calon data latih untuk integrasi CodeBERT fine-tuned di masa depan;
- **15% validation** sebagai calon data validasi;
- **15% testing** sebagai calon data uji.

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

Arsitektur RAG-LLM dinilai efektif apabila menunjukkan peningkatan dibanding Zero-Shot, terutama pada:

- peningkatan **Precision**, yang menunjukkan penurunan false positive dan halusinasi;
- peningkatan atau stabilitas **Recall**, yang menunjukkan kemampuan menemukan kerentanan aktual;
- peningkatan **F1-Score**, yang menunjukkan keseimbangan antara Precision dan Recall.

Metrik CodeBERT hanya dihitung jika Python bridge berhasil menjalankan inferensi CodeBERT lokal, baik melalui model fine-tuned yang dikonfigurasi maupun baseline embedding CodeBERT otomatis. Jika dependency lokal tidak tersedia, jalur CodeBERT tetap tercatat sebagai kegagalan terkontrol dan tidak dimasukkan ke metrik Bab IV.

Dengan demikian, keberhasilan sistem tidak hanya diukur dari banyaknya temuan, tetapi dari kemampuan menghasilkan temuan yang akurat dan dapat ditelusuri ke ground truth.

## 9. Artefak Sistem

Artefak yang dihasilkan oleh sistem meliputi:

- file audit JSON untuk skenario RAG-LLM, Zero-Shot, dan CodeBERT;
- file CSV dan Excel metrik evaluasi;
- file HTML interaktif untuk eksplorasi hasil;
- file Markdown `chapter-4-summary.md` sebagai ringkasan awal Bab IV;
- dataset CodeBERT bridge dalam format JSON dan CSV;
- prediksi CodeBERT bridge dari script Python lokal melalui baseline embedding otomatis atau model fine-tuned opsional;
- diagnostics console dan diagnostics Vertex AI Gemini yang mencatat status panggilan model dan retrieval live yang digunakan.

Artefak ini mendukung kebutuhan replikasi, audit metodologis, dan pelaporan hasil penelitian.

Report final menggunakan nama file tetap di dalam folder run dan dioverwrite secara atomic pada retry. Dengan demikian, percobaan lanjutan memperbarui artefak yang sama tanpa menumpuk file timestamp baru, sementara checkpoint per project tetap menjadi sumber resume.

## 10. Kesimpulan Rekayasa

`GeminiNuGetAuditor` direkayasa sebagai instrumen penelitian yang menggabungkan parsing dependency .NET, retrieval data advisory real-time dari GitHub GraphQL API, inferensi LLM, CodeBERT Python bridge lokal, dan evaluasi kuantitatif. Struktur ini memungkinkan pengujian empiris terhadap hipotesis bahwa RAG-LLM mampu mengurangi halusinasi dan meningkatkan kualitas deteksi kerentanan dibandingkan Zero-Shot, dengan jalur CodeBERT tetap otomatis namun hanya menghasilkan metrik ketika inferensi lokal real tersedia.
