# 🛡️ SCAM ALERT: Sistem Deteksi Pesan Penipuan Berbasis NLP

**Tugas Besar Kecerdasan Buatan**

Sistem deteksi otomatis untuk mengidentifikasi pesan penipuan (scam) menggunakan Natural Language Processing dan Machine Learning.

---

## 📋 Deskripsi Project

SCAM ALERT adalah aplikasi berbasis AI yang dapat mendeteksi pesan penipuan (scam) dan spam dengan menggunakan teknik Natural Language Processing (NLP) dan algoritma Machine Learning. Sistem ini menganalisis pola bahasa, kata kunci, dan struktur pesan untuk mengklasifikasikan apakah suatu pesan termasuk kategori penipuan atau legitimate.

### 🎯 Tujuan
- Melindungi pengguna dari pesan penipuan
- Mendeteksi spam dan phishing secara otomatis
- Memberikan confidence score untuk setiap prediksi
- Membantu edukasi tentang pola-pola penipuan digital

---

## ✨ Fitur Utama

1. **Multi-Model Classification**
   - Naive Bayes
   - Logistic Regression
   - Random Forest
   
2. **NLP Preprocessing**
   - Text cleaning dan normalisasi
   - Stopword removal (Bahasa Indonesia)
   - Stemming menggunakan Sastrawi
   - TF-IDF Vectorization

3. **Real-time Detection**
   - Analisis pesan secara instant
   - Confidence score untuk setiap prediksi
   - Identifikasi kata kunci mencurigakan

4. **Visualisasi & Evaluasi**
   - Confusion Matrix
   - Classification Report
   - Model Performance Comparison

---

## 🚀 Instalasi

### Prerequisites
- Python 3.8 atau lebih tinggi
- pip (Python package manager)

### Langkah Instalasi

1. **Clone atau download project ini**
```bash
cd scam-alert-project
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Jalankan program**
```bash
python main.py
```

---

## 📊 Dataset

Dataset terdiri dari **150+ pesan** yang dibagi menjadi:

### Kategori SCAM (Penipuan):
- Pesan undian palsu
- Phishing banking
- Investasi bodong
- Pinjaman online ilegal
- Hadiah palsu
- Verifikasi akun palsu

### Kategori LEGITIMATE (Aman):
- Komunikasi bisnis normal
- Reminder meeting/deadline
- Konfirmasi pesanan
- Pesan personal
- Notifikasi resmi

**Karakteristik Dataset:**
- 75 pesan scam (dengan variasi case)
- 75 pesan legitimate
- Balanced dataset untuk training optimal
- Data dalam Bahasa Indonesia dan Inggris

---

## 🧠 Algoritma & Metodologi

### 1. **Text Preprocessing**
```
Input → Lowercase → Remove URL → Remove Special Chars 
→ Stopword Removal → Stemming → Clean Text
```

### 2. **Feature Extraction**
- **TF-IDF (Term Frequency-Inverse Document Frequency)**
  - Max features: 1000
  - Mengubah teks menjadi numerical features

### 3. **Classification Models**

#### a. **Naive Bayes (MultinomialNB)**
- Algoritma probabilistik
- Efektif untuk text classification
- Fast training dan prediction

#### b. **Logistic Regression**
- Linear classifier
- Good interpretability
- Robust untuk binary classification

#### c. **Random Forest**
- Ensemble learning
- High accuracy
- Feature importance analysis

### 4. **Evaluation Metrics**
- Accuracy Score
- Precision, Recall, F1-Score
- Confusion Matrix
- Cross-validation

---

## 📈 Hasil & Performance

### Model Performance (Expected)

| Model | Accuracy | Precision | Recall |
|-------|----------|-----------|--------|
| Naive Bayes | ~92% | ~91% | ~93% |
| Logistic Regression | ~94% | ~93% | ~95% |
| Random Forest | ~96% | ~95% | ~97% |

### Confusion Matrix
![Model Evaluation](model_evaluation.png)

*Grafik otomatis di-generate setelah menjalankan program*

---

## 💻 Cara Penggunaan

### 1. Training Model
```python
from main import ScamDetector

detector = ScamDetector()
df = detector.create_dataset()
detector.train_models(df)
detector.save_model()
```

### 2. Load dan Predict
```python
detector = ScamDetector()
detector.load_model('scam_detector_model.pkl')

message = "SELAMAT! Anda menang 100 juta! Transfer admin fee 500rb"
result = detector.predict(message)

print(f"Prediksi: {result['prediction']}")
print(f"Confidence: {result['confidence']:.2f}%")
```

### 3. Testing dengan Pesan Baru
```python
test_messages = [
    "Urgent! Akun Anda akan diblokir. Klik link ini!",
    "Hai, besok meeting jam 2 ya",
]

for msg in test_messages:
    result = detector.predict(msg)
    if result['is_scam']:
        print(f"⚠️ SCAM: {msg}")
    else:
        print(f"✅ SAFE: {msg}")
```

---

## 🎨 Demo Interface

Project ini juga menyertakan **Web Interface** berbasis React untuk demo interaktif:

### Fitur Demo:
- Input pesan real-time
- Visualisasi hasil deteksi
- Confidence score indicator
- Contoh pesan untuk testing
- Warning system untuk pesan berbahaya

---

## 📁 Struktur Project

```
scam-alert-project/
│
├── main.py                      # Main program
├── requirements.txt             # Dependencies
├── README.md                    # Dokumentasi
├── scam_detector_model.pkl      # Saved model (setelah training)
├── model_evaluation.png         # Grafik evaluasi (setelah training)
│
└── demo/                        # Optional: Web demo
    └── scam_detector_demo.html
```

---

## 🔍 Contoh Output Program

```
============================================================
🛡️  SCAM ALERT: Sistem Deteksi Pesan Penipuan Berbasis NLP
============================================================

📁 Membuat dataset...
✅ Dataset berhasil dibuat: 150 pesan
   - Scam: 75 pesan
   - Legitimate: 75 pesan

🔄 Preprocessing data...
🔄 Vectorizing teks dengan TF-IDF...

🤖 Training Naive Bayes...
✅ Naive Bayes Accuracy: 0.9333

🤖 Training Logistic Regression...
✅ Logistic Regression Accuracy: 0.9667

🤖 Training Random Forest...
✅ Random Forest Accuracy: 0.9667

📊 Grafik evaluasi disimpan: model_evaluation.png

============================================================
🧪 Testing Sistem dengan Contoh Pesan
============================================================

📩 Pesan 1: SELAMAT! Anda menang undian 100 juta!
   ⚠️  DETEKSI: PENIPUAN (Confidence: 98.45%)

📩 Pesan 2: Hai, besok meeting jam 2 ya
   ✅ DETEKSI: AMAN (Confidence: 95.32%)
```

---

## 🎓 Penjelasan Teknis

### Mengapa NLP?
Natural Language Processing memungkinkan komputer memahami bahasa manusia dengan:
- Mengekstrak fitur dari teks
- Memahami konteks dan semantik
- Mengenali pola linguistik
- Mengklasifikasikan intent pesan

### Mengapa TF-IDF?
- Memberikan bobot pada kata-kata penting
- Mengurangi pengaruh kata umum
- Representasi numerik yang efektif
- Scalable untuk dataset besar

### Mengapa Multiple Models?
- Membandingkan performance
- Ensemble prediction untuk akurasi lebih tinggi
- Robustness terhadap berbagai jenis pesan

---

## 🛠️ Pengembangan Lebih Lanjut

### Improvement Ideas:
1. **Expand Dataset**
   - Tambah data dari sumber real
   - Scraping dari forum/social media
   - Crowdsourcing data labeling

2. **Deep Learning**
   - Implementasi LSTM/GRU
   - Transformers (BERT)
   - Word embeddings (Word2Vec, GloVe)

3. **Additional Features**
   - URL analysis
   - Email header inspection
   - Image-based scam detection
   - Multi-language support

4. **Deployment**
   - REST API dengan Flask/FastAPI
   - Web app dengan Streamlit
   - Mobile app integration
   - Browser extension

---

## 📚 Referensi

1. **Natural Language Processing**
   - Bird, S., Klein, E., & Loper, E. (2009). Natural Language Processing with Python
   
2. **Machine Learning**
   - Scikit-learn Documentation
   - Hastie, T., Tibshirani, R., & Friedman, J. (2009). The Elements of Statistical Learning

3. **Text Classification**
   - Manning, C. D., & Schütze, H. (1999). Foundations of Statistical Natural Language Processing

4. **Sastrawi (Indonesian NLP)**
   - https://github.com/sastrawi/sastrawi

---

## 👨‍💻 Author

**Muhammad Reza Fadillah**
- Mata Kuliah: Kecerdasan Buatan

---

## 📝 Lisensi

Project ini dibuat untuk keperluan akademik - Tugas Besar Kecerdasan Buatan

---

## 🤝 Kontribusi

Feedback dan saran untuk improvement sangat diterima! Silakan buat issue atau pull request.

---

## ⚠️ Disclaimer

Sistem ini adalah prototype untuk tujuan pembelajaran. Untuk implementasi production, diperlukan:
- Dataset yang lebih besar dan beragam
- Continuous model retraining
- Security testing yang komprehensif
- Compliance dengan regulasi privasi data

---


**🛡️ Stay Safe from Scams! 🛡️**
