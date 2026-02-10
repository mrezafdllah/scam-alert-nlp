from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
from main import ScamDetector
from ocr_utils import ImageTextExtractor

app = Flask(__name__)
CORS(app)

# Konfigurasi upload
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff', 'webp'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create upload folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize detector and OCR
detector = ScamDetector()
ocr_extractor = ImageTextExtractor()

# Load model
MODEL_PATH = 'scam_detector_model.pkl'
if os.path.exists(MODEL_PATH):
    detector.load_model(MODEL_PATH)
    print(f"✅ Model loaded from {MODEL_PATH}")
else:
    print(f"⚠️  Model not found. Please run main.py first to train the model.")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    """Serve the main interface dengan fitur OCR"""
    html_content = r'''<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCAM ALERT - Deteksi Pesan Penipuan untuk Lancia berbasis NLP</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: white;
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            text-align: center;
        }
        .header h1 { color: #667eea; font-size: 2.5em; margin-bottom: 10px; }
        .header p { color: #666; font-size: 1.1em; }
        .feature-badge {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: bold;
            margin: 10px 5px;
            background: #e3f2fd;
            color: #1976d2;
        }
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        @media (max-width: 768px) {
            .main-content { grid-template-columns: 1fr; }
        }
        .card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        .card h2 { color: #333; margin-bottom: 20px; font-size: 1.5em; }
        
        /* Tabs untuk Input Method */
        .input-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }
        .tab-btn {
            flex: 1;
            padding: 15px;
            border: none;
            background: none;
            color: #666;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        .tab-btn:hover { color: #667eea; }
        .tab-btn.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        
        /* Upload Area */
        .upload-area {
            border: 3px dashed #667eea;
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: #f8f9ff;
        }
        .upload-area:hover {
            background: #e8ebff;
            border-color: #5568d3;
        }
        .upload-area.drag-over {
            background: #d4d9ff;
            border-color: #4451b8;
        }
        .upload-icon {
            font-size: 4em;
            margin-bottom: 15px;
            color: #667eea;
        }
        .upload-text {
            color: #666;
            font-size: 16px;
            margin-bottom: 10px;
        }
        .upload-hint {
            color: #999;
            font-size: 13px;
        }
        #imageInput {
            display: none;
        }
        
        /* Image Preview */
        .image-preview {
            display: none;
            margin-top: 20px;
            position: relative;
        }
        .image-preview.show {
            display: block;
        }
        .preview-img {
            max-width: 100%;
            max-height: 300px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        .remove-image {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #ff6b6b;
            color: white;
            border: none;
            border-radius: 50%;
            width: 35px;
            height: 35px;
            font-size: 20px;
            cursor: pointer;
            box-shadow: 0 3px 10px rgba(0,0,0,0.3);
        }
        .remove-image:hover {
            background: #ee5a6f;
        }
        
        /* OCR Progress */
        .ocr-progress {
            display: none;
            background: #e3f2fd;
            border-radius: 10px;
            padding: 20px;
            margin-top: 15px;
            text-align: center;
        }
        .ocr-progress.show { display: block; }
        .ocr-spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #2196f3;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        
        /* Voice Controls */
        .voice-controls {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        .btn-voice {
            flex: 1;
            padding: 15px;
            border: 2px solid #4caf50;
            border-radius: 10px;
            background: white;
            color: #4caf50;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        .btn-voice:hover { background: #4caf50; color: white; }
        .btn-voice.recording {
            background: #f44336;
            color: white;
            border-color: #f44336;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        textarea {
            width: 100%;
            height: 200px;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            resize: vertical;
            transition: border-color 0.3s;
        }
        textarea:focus { outline: none; border-color: #667eea; }
        
        .button-group { display: flex; gap: 10px; margin-top: 15px; }
        button {
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        .btn-primary {
            flex: 1;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-secondary { background: #f5f5f5; color: #666; }
        .btn-secondary:hover { background: #e0e0e0; }
        
        .btn-speaker {
            background: linear-gradient(135deg, #ff9800 0%, #ff5722 100%);
            color: white;
            padding: 20px 40px;
            border-radius: 15px;
            font-size: 18px;
            margin-top: 20px;
            width: 100%;
        }
        .btn-speaker:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(255, 152, 0, 0.5);
        }
        .btn-speaker.speaking { animation: speakPulse 0.8s infinite; }
        @keyframes speakPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .result { display: none; }
        .result.show { display: block; }
        .result-header {
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 20px;
            text-align: center;
        }
        .result-scam {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
        }
        .result-safe {
            background: linear-gradient(135deg, #51cf66 0%, #37b24d 100%);
            color: white;
        }
        .result-header h3 { font-size: 2em; margin-bottom: 10px; }
        .confidence-bar {
            background: rgba(255,255,255,0.3);
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin-top: 15px;
        }
        .confidence-fill {
            height: 100%;
            background: white;
            transition: width 1s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        
        .info-box {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            border-radius: 10px;
            margin-top: 15px;
        }
        .info-box h4 { color: #667eea; margin-bottom: 8px; }
        
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 10px;
            margin-top: 15px;
        }
        .warning-box ul { margin-left: 20px; margin-top: 10px; }
        
        .loading { display: none; text-align: center; padding: 40px; }
        .loading.show { display: block; }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        .stat-card h3 { color: #666; font-size: 0.9em; margin-bottom: 10px; }
        .stat-card .number { font-size: 2.5em; font-weight: bold; color: #667eea; }
        
        .examples { margin-top: 20px; }
        .example-item {
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 14px;
        }
        .example-item:hover { border-color: #667eea; background: #f8f9ff; }
        .example-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: bold;
            margin-right: 8px;
        }
        .badge-scam { background: #fee; color: #c33; }
        .badge-safe { background: #efe; color: #3c3; }
        
        .footer { text-align: center; color: white; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SCAM ALERT</h1>
            <p>Sistem Deteksi Pesan Penipuan berbasis NLP</p>
            <div>
                <span class="feature-badge">📸 OCR Support</span>
                <span class="feature-badge">🎤 Voice Input</span>
                <span class="feature-badge">🔊 Text-to-Speech</span>
                <span class="feature-badge">🤖 AI Detection</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>Total Analyzed</h3>
                <div class="number" id="totalCount">0</div>
            </div>
            <div class="stat-card">
                <h3>Scam Detected</h3>
                <div class="number" style="color: #ff6b6b;" id="scamCount">0</div>
            </div>
            <div class="stat-card">
                <h3>Safe Messages</h3>
                <div class="number" style="color: #51cf66;" id="safeCount">0</div>
            </div>
        </div>

        <div class="main-content">
            <div class="card">
                <h2>📝 Input Pesan</h2>
                
                <!-- Tabs -->
                <div class="input-tabs">
                    <button class="tab-btn active" data-tab="text">✍️ Ketik Manual</button>
                    <button class="tab-btn" data-tab="image">📸 Upload Gambar</button>
                    <button class="tab-btn" data-tab="voice">🎤 Rekam Suara</button>
                </div>
                
                <!-- Tab: Text Input -->
                <div id="tab-text" class="tab-content active">
                    <textarea id="messageInput" placeholder="Ketik atau paste pesan yang ingin dianalisis..."></textarea>
                </div>
                
                <!-- Tab: Image Upload -->
                <div id="tab-image" class="tab-content">
                    <div class="upload-area" id="uploadArea">
                        <div class="upload-icon">📸</div>
                        <div class="upload-text">Klik atau Drag & Drop Gambar</div>
                        <div class="upload-hint">Format: PNG, JPG, JPEG (Max 10MB)</div>
                    </div>
                    <input type="file" id="imageInput" accept="image/*">
                    
                    <div class="image-preview" id="imagePreview">
                        <button class="remove-image" id="removeImage">×</button>
                        <img id="previewImg" class="preview-img" alt="Preview">
                    </div>
                    
                    <div class="ocr-progress" id="ocrProgress">
                        <div class="ocr-spinner"></div>
                        <div>Memproses gambar dan ekstraksi teks...</div>
                    </div>
                    
                    <textarea id="extractedText" placeholder="Teks hasil ekstraksi akan muncul di sini..." style="margin-top: 15px;"></textarea>
                </div>
                
                <!-- Tab: Voice Input -->
                <div id="tab-voice" class="tab-content">
                    <div class="voice-controls">
                        <button class="btn-voice" id="voiceBtn">
                            🎤 <span id="voiceBtnText">Tekan untuk Mulai Rekam</span>
                        </button>
                    </div>
                    <div style="background: #e3f2fd; padding: 15px; border-radius: 10px; margin-bottom: 15px; text-align: center;">
                        <div id="voiceStatus">Tekan tombol mikrofon dan mulai berbicara</div>
                    </div>
                    <textarea id="voiceText" placeholder="Teks hasil rekaman akan muncul di sini..."></textarea>
                </div>
                
                <select id="modelSelector" style="width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 10px; margin-top: 15px; font-size: 14px;">
                    <option value="Random Forest">🌲 Random Forest (Recommended)</option>
                    <option value="Logistic Regression">📊 Logistic Regression</option>
                    <option value="Naive Bayes">🎯 Naive Bayes</option>
                </select>

                <div class="button-group">
                    <button class="btn-primary" id="analyzeBtn">🔍 Analisis Sekarang</button>
                    <button class="btn-secondary" id="clearBtn">🗑️ Clear All</button>
                </div>

                <div class="examples">
                    <h3 style="margin-bottom: 15px; color: #666;">📋 Contoh Pesan:</h3>
                    <div class="example-item">
                        <span class="example-badge badge-scam">⚠️ SCAM</span>
                        SELAMAT! Anda menang undian Rp 100 juta! Transfer biaya admin
                    </div>
                    <div class="example-item">
                        <span class="example-badge badge-scam">⚠️ SCAM</span>
                        URGENT! Akun bank akan diblokir! Klik link ini
                    </div>
                    <div class="example-item">
                        <span class="example-badge badge-safe">✅ SAFE</span>
                        Meeting tim besok jam 10 pagi di ruang meeting
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>📊 Hasil Analisis</h2>
                
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>Menganalisis pesan...</p>
                </div>

                <div class="result" id="result">
                    <div class="result-header" id="resultHeader">
                        <h3 id="resultTitle"></h3>
                        <p id="resultModel"></p>
                        <div class="confidence-bar">
                            <div class="confidence-fill" id="confidenceFill"></div>
                        </div>
                    </div>

                    <div class="info-box">
                        <h4>💡 Rekomendasi</h4>
                        <p id="recommendation"></p>
                    </div>

                    <div class="warning-box" id="warningBox" style="display: none;">
                        <h4>⚠️ Peringatan Keamanan</h4>
                        <ul>
                            <li>Jangan klik link yang mencurigakan</li>
                            <li>Jangan berikan data pribadi (KTP, password, PIN)</li>
                            <li>Jangan transfer uang ke rekening tidak dikenal</li>
                            <li>Verifikasi langsung dengan sumber resmi</li>
                        </ul>
                    </div>
                    
                    <button class="btn-speaker" id="speakBtn" style="display: none;">
                        🔊 <span id="speakBtnText">DENGARKAN HASIL</span>
                    </button>
                </div>

                <div style="text-align: center; color: #999; padding: 40px;" id="placeholder">
                    <div style="font-size: 4em;">🛡️</div>
                    <p>Pilih metode input dan mulai analisis</p>
                </div>
            </div>
        </div>

        <div class="footer">
            <p><strong>SCAM ALERT NLP v2.0 - With OCR & Voice Support</strong></p>
            <p><strong>TUGAS BESAR KECERDASAN BUATAN</strong></p>
            <p><strong>POLITEKNIK NEGERI INDRAMAYU</strong></p>
            <p><strong>PRODI SISTEM INFORMASI KOTA CERDAS</strong></p>
            <p>Powered by Muhammad Rijal Marzuq | Widuri Hazimah Zahra | Muhammad Reza Fadillah</p>
        </div>
    </div>

    <script>
        let stats = { total: 0, scam: 0, safe: 0 };
        let currentResult = null;
        let recognition = null;
        let synthesis = window.speechSynthesis;
        let currentTab = 'text';
        let uploadedImage = null;

        // Tab Switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                btn.classList.add('active');
                currentTab = btn.dataset.tab;
                document.getElementById(`tab-${currentTab}`).classList.add('active');
            });
        });

        // Image Upload
        const uploadArea = document.getElementById('uploadArea');
        const imageInput = document.getElementById('imageInput');
        const imagePreview = document.getElementById('imagePreview');
        const previewImg = document.getElementById('previewImg');
        const removeImage = document.getElementById('removeImage');
        const ocrProgress = document.getElementById('ocrProgress');
        const extractedText = document.getElementById('extractedText');

        uploadArea.addEventListener('click', () => imageInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) {
                handleImageUpload(file);
            }
        });

        imageInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) handleImageUpload(file);
        });

        removeImage.addEventListener('click', () => {
            uploadedImage = null;
            imageInput.value = '';
            imagePreview.classList.remove('show');
            extractedText.value = '';
            ocrProgress.classList.remove('show');
        });

        async function handleImageUpload(file) {
            uploadedImage = file;
            
            // Preview
            const reader = new FileReader();
            reader.onload = (e) => {
                previewImg.src = e.target.result;
                imagePreview.classList.add('show');
            };
            reader.readAsDataURL(file);

            // OCR Processing
            ocrProgress.classList.add('show');
            extractedText.value = 'Memproses...';

            const formData = new FormData();
            formData.append('image', file);

            try {
                const response = await fetch('/api/ocr', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                
                if (data.success && data.text) {
                    extractedText.value = data.text;
                    if (data.confidence) {
                        extractedText.placeholder = `Confidence: ${data.confidence}% | ${data.word_count} kata`;
                    }
                } else {
                    extractedText.value = 'Tidak dapat mengekstrak teks dari gambar.';
                    if (data.error) {
                        extractedText.value += '\nError: ' + data.error;
                    }
                }
            } catch (error) {
                extractedText.value = 'Error: ' + error.message;
            } finally {
                ocrProgress.classList.remove('show');
            }
        }

        // Voice Recognition
        function initSpeechRecognition() {
            if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
                const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
                recognition = new SpeechRecognition();
                recognition.lang = 'id-ID';
                recognition.continuous = false;

                recognition.onstart = () => {
                    voiceBtn.classList.add('recording');
                    voiceBtnText.textContent = 'Mendengarkan...';
                    voiceStatus.textContent = '🎤 Sedang mendengarkan... Silakan bicara';
                };

                recognition.onresult = (event) => {
                    const transcript = event.results[0][0].transcript;
                    document.getElementById('voiceText').value = transcript;
                    voiceStatus.textContent = '✅ Selesai: "' + transcript + '"';
                };

                recognition.onerror = (event) => {
                    voiceStatus.textContent = '❌ Error: ' + event.error;
                };

                recognition.onend = () => {
                    voiceBtn.classList.remove('recording');
                    voiceBtnText.textContent = 'Tekan untuk Mulai Rekam';
                };
            }
        }

        document.getElementById('voiceBtn').addEventListener('click', () => {
            if (!recognition) {
                alert('Speech recognition tidak tersedia');
                return;
            }
            recognition.start();
        });

        // Text-to-Speech
        document.getElementById('speakBtn').addEventListener('click', () => {
            if (!currentResult) return;
            
            synthesis.cancel();
            
            let text = '';
            if (currentResult.is_scam) {
                text = `Peringatan! Pesan ini terdeteksi sebagai penipuan. Tingkat keyakinan ${Math.round(currentResult.confidence)} persen. ${currentResult.recommendation}. `;
                text += `Peringatan Keamanan: `;
                text += `Jangan klik link yang mencurigakan. `;
                text += `Jangan berikan data pribadi seperti KTP, password, atau PIN. `;
                text += `Jangan transfer uang ke rekening tidak dikenal. `;
                text += `Verifikasi langsung dengan sumber resmi.`;
            } else {
                text = `Pesan ini aman. Tingkat keyakinan ${Math.round(currentResult.confidence)} persen. ${currentResult.recommendation}`;
            }
            
            const utterance = new SpeechSynthesisUtterance(text);
            utterance.lang = 'id-ID';
            utterance.rate = 0.9;
            
            utterance.onstart = () => {
                document.getElementById('speakBtn').classList.add('speaking');
                document.getElementById('speakBtnText').textContent = 'SEDANG MEMBACA...';
            };
            
            utterance.onend = () => {
                document.getElementById('speakBtn').classList.remove('speaking');
                document.getElementById('speakBtnText').textContent = 'DENGARKAN HASIL';
            };
            
            synthesis.speak(utterance);
        });

        // Analyze Button
        document.getElementById('analyzeBtn').addEventListener('click', async () => {
            let message = '';
            
            if (currentTab === 'text') {
                message = document.getElementById('messageInput').value.trim();
            } else if (currentTab === 'image') {
                message = extractedText.value.trim();
            } else if (currentTab === 'voice') {
                message = document.getElementById('voiceText').value.trim();
            }
            
            if (!message) {
                alert('Mohon masukkan pesan atau upload gambar!');
                return;
            }

            document.getElementById('placeholder').style.display = 'none';
            document.getElementById('result').classList.remove('show');
            document.getElementById('loading').classList.add('show');

            try {
                const response = await fetch('/api/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: message,
                        model_name: document.getElementById('modelSelector').value
                    })
                });

                const data = await response.json();
                if (data.success) {
                    currentResult = data;
                    displayResult(data);
                    updateStats(data.is_scam);
                    document.getElementById('speakBtn').style.display = 'flex';
                }
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                document.getElementById('loading').classList.remove('show');
            }
        });

        // Clear Button
        document.getElementById('clearBtn').addEventListener('click', () => {
            document.getElementById('messageInput').value = '';
            document.getElementById('voiceText').value = '';
            extractedText.value = '';
            if (uploadedImage) {
                removeImage.click();
            }
            document.getElementById('result').classList.remove('show');
            document.getElementById('placeholder').style.display = 'block';
            synthesis.cancel();
        });

        // Examples
        document.querySelectorAll('.example-item').forEach(item => {
            item.addEventListener('click', () => {
                const text = item.textContent.replace(/^(⚠️ SCAM|✅ SAFE)\s*/, '').trim();
                document.getElementById('messageInput').value = text;
                document.querySelector('[data-tab="text"]').click();
            });
        });

        function displayResult(data) {
            const resultHeader = document.getElementById('resultHeader');
            const resultTitle = document.getElementById('resultTitle');
            const resultModel = document.getElementById('resultModel');
            const confidenceFill = document.getElementById('confidenceFill');
            const recommendation = document.getElementById('recommendation');
            const warningBox = document.getElementById('warningBox');
            
            if (data.is_scam) {
                resultHeader.className = 'result-header result-scam';
                resultTitle.textContent = '⚠️ SCAM DETECTED';
                warningBox.style.display = 'block';
            } else {
                resultHeader.className = 'result-header result-safe';
                resultTitle.textContent = '✅ SAFE MESSAGE';
                warningBox.style.display = 'none';
            }
            
            resultModel.textContent = `Model: ${data.model} | Risk: ${data.risk_level.toUpperCase()}`;
            confidenceFill.style.width = '0%';
            setTimeout(() => {
                confidenceFill.style.width = data.confidence + '%';
                confidenceFill.textContent = data.confidence.toFixed(1) + '%';
            }, 100);
            
            recommendation.textContent = data.recommendation;
            document.getElementById('result').classList.add('show');
        }

        function updateStats(isScam) {
            stats.total++;
            if (isScam) stats.scam++;
            else stats.safe++;
            document.getElementById('totalCount').textContent = stats.total;
            document.getElementById('scamCount').textContent = stats.scam;
            document.getElementById('safeCount').textContent = stats.safe;
        }

        // Initialize
        window.addEventListener('load', () => {
            initSpeechRecognition();
        });
    </script>
</body>
</html>'''
    return render_template_string(html_content)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'model_loaded': os.path.exists(MODEL_PATH),
        'ocr_available': True
    })

@app.route('/api/ocr', methods=['POST'])
def ocr_extract():
    """
    Extract text from uploaded image using OCR
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided'
            }), 400
        
        file = request.files['image']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Invalid file format. Use PNG, JPG, JPEG, BMP, TIFF, or WEBP'
            }), 400
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Extract text using OCR
            result = ocr_extractor.extract_with_fallback(filepath)
            
            # Delete temporary file
            os.remove(filepath)
            
            return jsonify(result)
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(filepath):
                os.remove(filepath)
            raise e
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/predict', methods=['POST'])
def predict():
    """Predict whether a message is scam or not"""
    try:
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({'error': 'Missing message field'}), 400
        
        message = data['message']
        model_name = data.get('model_name', 'Random Forest')
        
        if not message.strip():
            return jsonify({'error': 'Message cannot be empty'}), 400
        
        result = detector.predict(message, model_name=model_name)
        
        confidence = result['confidence']
        if confidence > 80:
            risk_level = 'critical' if result['is_scam'] else 'low'
        elif confidence > 60:
            risk_level = 'high' if result['is_scam'] else 'low'
        elif confidence > 40:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        if result['is_scam']:
            recommendation = "Kemungkinan besar ini adalah pesan penipuan. Jangan berikan informasi pribadi atau transfer uang."
        else:
            recommendation = "Pesan ini tampak aman. Namun tetap berhati-hati dengan informasi sensitif."
        
        return jsonify({
            'success': True,
            'prediction': result['prediction'],
            'is_scam': result['is_scam'],
            'confidence': round(confidence, 2),
            'risk_level': risk_level,
            'model': model_name,
            'recommendation': recommendation
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/predict/batch', methods=['POST'])
def predict_batch():
    """Predict multiple messages at once"""
    try:
        data = request.get_json()
        
        if not data or 'messages' not in data:
            return jsonify({'error': 'Missing messages field'}), 400
        
        messages = data['messages']
        model_name = data.get('model_name', 'Random Forest')
        
        results = []
        for message in messages:
            if message.strip():
                result = detector.predict(message, model_name=model_name)
                results.append({
                    'message': message,
                    'prediction': result['prediction'],
                    'is_scam': result['is_scam'],
                    'confidence': round(result['confidence'], 2)
                })
        
        return jsonify({
            'success': True,
            'total': len(results),
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🛡️  SCAM ALERT - Flask API Server with OCR Support")
    print("="*70)
    
    if not os.path.exists(MODEL_PATH):
        print("\n⚠️  WARNING: Model file not found!")
        print("   Please run 'python main.py' first to train the model.\n")
    
    print("\n🚀 Starting server...")
    print("   API Endpoint: http://localhost:5000")
    print("   Interface: http://localhost:5000")
    print("\n📋 Available endpoints:")
    print("   GET  /                    - Web interface with OCR")
    print("   POST /api/ocr             - Extract text from image")
    print("   POST /api/predict         - Single prediction")
    print("   POST /api/predict/batch   - Batch prediction")
    print("\n   Press Ctrl+C to stop")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)