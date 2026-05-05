# Copilot Instructions

## Project Guidelines
- Hindari duplikasi konfigurasi: jika dua key appsettings fungsinya sama, gunakan satu key yang paling relevan.
- Konfigurasi harus membaca dari appsettings.json saja, ditambah dengan environment variable.

## Model Evaluation
- Untuk evaluasi kinerja model, gunakan rumus: Accuracy=(TP+TN)/(TP+TN+FP+FN), Precision=TP/(TP+FP), Recall=TP/(TP+FN), F1=2*(Precision*Recall)/(Precision+Recall).
- Kriteria keberhasilan penelitian: RAG-LLM harus menunjukkan Precision jauh lebih tinggi dan False Positive lebih rendah dibanding LLM konvensional tanpa RAG.