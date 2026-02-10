# ⚡ QUICK START GUIDE

## 🚀 Get Started in 3 Minutes!

### Step 1: Install Dependencies (1 min)
```bash
pip install pandas numpy scikit-learn matplotlib seaborn Sastrawi
```

### Step 2: Run Training (1 min)
```bash
python main.py
```

**Expected Output:**
```
🛡️  SCAM ALERT: Sistem Deteksi Pesan Penipuan Berbasis NLP
================================================================

📁 Generating dataset...
   ✅ Dataset created: 300+ messages

🤖 Training Naive Bayes...
   ✅ Accuracy: 0.9333

🤖 Training Logistic Regression...
   ✅ Accuracy: 0.9500

🤖 Training Random Forest...
   ✅ Accuracy: 0.9667

🏆 Best Model: Random Forest (Accuracy: 0.9667)

💾 Model saved: scam_detector_model.pkl
📊 Dashboard saved: model_evaluation_dashboard.png

✨ IMPLEMENTASI SELESAI!
```

### Step 3: Test System (1 min)
```bash
python test_detector.py
```

**Choose option:**
- **1** = Interactive (type your own messages)
- **2** = Auto test suite (comprehensive testing)
- **3** = Quick examples

---

## 📝 Quick Test Examples

### Test 1: Scam Message
```python
from main import ScamDetector

detector = ScamDetector()
detector.load_model('scam_detector_model.pkl')

# Test scam
result = detector.predict("SELAMAT! Anda menang 100 juta! Transfer 500rb sekarang!")
print(f"Scam: {result['is_scam']}, Confidence: {result['confidence']:.1f}%")
# Output: Scam: True, Confidence: 98.2%
```

### Test 2: Safe Message
```python
result = detector.predict("Meeting besok jam 2 siang. Jangan lupa bawa dokumen")
print(f"Scam: {result['is_scam']}, Confidence: {result['confidence']:.1f}%")
# Output: Scam: False, Confidence: 96.5%
```

---

## 🎮 Interactive Mode

```bash
python test_detector.py
# Select: 1 (Interactive Mode)

# Then type:
📝 Enter message: URGENT! Transfer 500rb untuk klaim hadiah 10 juta!

# Result:
⚠️  DETEKSI: PENIPUAN
🎯 Confidence: 97.8%
🚨 WARNING: Jangan berikan info pribadi/transfer uang!
```

---

## 🧪 Run All Tests

```bash
python test_detector.py
# Select: 2 (Run Test Suite)
```

This will test:
- ✅ Fake lottery messages
- ✅ Phishing attempts
- ✅ Investment scams
- ✅ Legitimate business messages
- ✅ Personal communications

---

## 🔬 Advanced Simulation

```bash
python advanced_simulation.py

# Features:
# 1. Real-time message stream (live monitoring)
# 2. Detection pattern analysis (with graphs)
# 3. Edge case testing (boundary conditions)
# 4. Performance stress test (100+ messages)
# 5. Model comparison (3 algorithms side-by-side)
```

---

## 📊 Output Files

After running the programs, you'll have:

| File | Description | Size |
|------|-------------|------|
| `scam_detector_model.pkl` | Trained model | ~500KB |
| `model_evaluation_dashboard.png` | Performance graphs | ~200KB |
| `simulation_analysis.png` | Simulation results | ~150KB |

---

## 🐛 Troubleshooting

### Error: "No module named 'Sastrawi'"
```bash
pip install Sastrawi
```

### Error: "Model not found"
```bash
# Run training first:
python main.py
```

### Grafik tidak muncul
```bash
# Files are automatically saved as PNG
# Check: model_evaluation_dashboard.png
```

---

## 💡 Pro Tips

### 1. Test Your Own Messages
```python
messages = [
    "Your suspicious message here",
    "Another message to test",
]

for msg in messages:
    result = detector.predict(msg)
    print(f"{msg[:40]}... → {'SCAM' if result['is_scam'] else 'SAFE'}")
```

### 2. Compare All Models
```bash
python test_detector.py
# Select: 6 (Compare Models)
# Enter your message
```

### 3. Batch Processing
```python
import pandas as pd

messages = ["message1", "message2", "message3"]
results = detector.batch_predict(messages)
print(results)  # Returns DataFrame
```

---

## 📚 What's Next?

1. ✅ **Understand the code**: Read `main.py` comments
2. ✅ **Experiment**: Try different messages
3. ✅ **Analyze**: Check visualization graphs
4. ✅ **Modify**: Add your own scam categories
5. ✅ **Improve**: Expand the dataset

---

## 🎯 Key Commands Summary

```bash
# Training
python main.py

# Basic Testing
python test_detector.py

# Advanced Simulation
python advanced_simulation.py

# Check Files
ls -lh *.pkl *.png
```

---

## ✨ You're Ready!

Everything is set up and ready to use. Start testing with your own messages!

**Need help?** Check README.md for detailed documentation.

---

**Quick Links:**
- 📖 Full documentation: `README.md`
- 🔧 Main implementation: `main.py`
- 🧪 Testing script: `test_detector.py`
- 🔬 Advanced features: `advanced_simulation.py`