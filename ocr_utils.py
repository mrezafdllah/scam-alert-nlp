"""
OCR Utilities untuk Scam Alert
Ekstraksi teks dari gambar menggunakan Tesseract OCR
"""

import pytesseract
from PIL import Image
import cv2
import numpy as np
import os
import re

# Konfigurasi Tesseract (sesuaikan path jika perlu)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
# Linux/Mac: biasanya sudah otomatis detect

class ImageTextExtractor:
    def __init__(self):
        self.supported_formats = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.webp']
        
    def preprocess_image(self, image):
        """
        Preprocessing gambar untuk meningkatkan akurasi OCR
        """
        # Convert PIL Image to numpy array
        img_array = np.array(image)
        
        # Convert to grayscale
        if len(img_array.shape) == 3:
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
        else:
            gray = img_array
        
        # Apply thresholding untuk meningkatkan kontras
        # Method 1: Adaptive threshold (bagus untuk berbagai kondisi lighting)
        processed = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
            cv2.THRESH_BINARY, 11, 2
        )
        
        # Noise removal
        processed = cv2.medianBlur(processed, 3)
        
        # Dilate untuk menyambungkan teks yang terputus
        kernel = np.ones((1, 1), np.uint8)
        processed = cv2.dilate(processed, kernel, iterations=1)
        
        # Erode untuk menghilangkan noise
        processed = cv2.erode(processed, kernel, iterations=1)
        
        return processed
    
    def extract_text(self, image_file, preprocess=True):
        """
        Ekstraksi teks dari gambar
        
        Args:
            image_file: File gambar (dapat berupa path atau file object)
            preprocess: Apakah melakukan preprocessing (default: True)
        
        Returns:
            dict: {
                'success': bool,
                'text': str,
                'confidence': float,
                'word_count': int,
                'error': str (jika ada)
            }
        """
        try:
            # Load image
            if isinstance(image_file, str):
                image = Image.open(image_file)
            else:
                image = Image.open(image_file)
            
            # Convert RGBA to RGB jika perlu
            if image.mode == 'RGBA':
                image = image.convert('RGB')
            
            # Preprocessing
            if preprocess:
                processed_img = self.preprocess_image(image)
                # Convert back to PIL Image
                image_for_ocr = Image.fromarray(processed_img)
            else:
                image_for_ocr = image
            
            # Konfigurasi OCR
            # --psm 6: Assume uniform block of text
            # --oem 3: Use LSTM OCR Engine only
            custom_config = r'--oem 3 --psm 6'
            
            # Ekstrak teks dengan confidence
            ocr_data = pytesseract.image_to_data(
                image_for_ocr, 
                lang='ind+eng',  # Support Indonesian & English
                config=custom_config,
                output_type=pytesseract.Output.DICT
            )
            
            # Filter dan ambil teks dengan confidence > 30
            text_parts = []
            confidences = []
            
            for i, conf in enumerate(ocr_data['conf']):
                if int(conf) > 30:  # Filter low confidence
                    text = ocr_data['text'][i].strip()
                    if text:
                        text_parts.append(text)
                        confidences.append(int(conf))
            
            # Gabungkan teks
            extracted_text = ' '.join(text_parts)
            
            # Hitung average confidence
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            # Clean text
            cleaned_text = self.clean_extracted_text(extracted_text)
            
            # Word count
            word_count = len(cleaned_text.split())
            
            return {
                'success': True,
                'text': cleaned_text,
                'raw_text': extracted_text,
                'confidence': round(avg_confidence, 2),
                'word_count': word_count,
                'has_text': bool(cleaned_text.strip())
            }
            
        except Exception as e:
            return {
                'success': False,
                'text': '',
                'confidence': 0,
                'word_count': 0,
                'error': str(e),
                'has_text': False
            }
    
    def clean_extracted_text(self, text):
        """
        Membersihkan teks hasil OCR dari noise
        """
        # Remove multiple spaces
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters yang sering muncul sebagai noise
        # Tapi tetap pertahankan karakter penting seperti Rp, %, dll
        text = re.sub(r'[|_~`]', '', text)
        
        # Fix common OCR errors
        replacements = {
            '0O': 'OO',  # O sering dibaca 0
            'l1': 'll',  # 1 sering dibaca l
            'rn': 'm',   # rn sering dibaca m
        }
        
        for old, new in replacements.items():
            text = text.replace(old, new)
        
        return text.strip()
    
    def validate_image(self, file):
        """
        Validasi file gambar
        """
        # Check file size (max 10MB)
        MAX_SIZE = 10 * 1024 * 1024  # 10MB
        
        try:
            # Get file extension
            filename = file.filename if hasattr(file, 'filename') else str(file)
            ext = os.path.splitext(filename)[1].lower()
            
            if ext not in self.supported_formats:
                return False, f"Format tidak didukung. Gunakan: {', '.join(self.supported_formats)}"
            
            # Check file size if possible
            if hasattr(file, 'content_length') and file.content_length:
                if file.content_length > MAX_SIZE:
                    return False, "Ukuran file terlalu besar (max 10MB)"
            
            return True, "Valid"
            
        except Exception as e:
            return False, str(e)
    
    def extract_with_fallback(self, image_file):
        """
        Ekstrak teks dengan fallback strategy
        Coba dengan preprocessing, jika gagal coba tanpa preprocessing
        """
        # Try with preprocessing
        result = self.extract_text(image_file, preprocess=True)
        
        # Jika tidak menemukan teks atau confidence rendah, coba tanpa preprocessing
        if not result['has_text'] or result['confidence'] < 40:
            result_no_preprocess = self.extract_text(image_file, preprocess=False)
            
            # Gunakan hasil yang lebih baik
            if result_no_preprocess['word_count'] > result['word_count']:
                result = result_no_preprocess
        
        return result


# Helper function untuk testing
def test_ocr(image_path):
    """
    Test OCR dengan file gambar
    """
    extractor = ImageTextExtractor()
    
    print(f"\n{'='*70}")
    print(f"🔍 Testing OCR pada: {image_path}")
    print(f"{'='*70}")
    
    result = extractor.extract_with_fallback(image_path)
    
    if result['success']:
        print(f"\n✅ Ekstraksi berhasil!")
        print(f"📊 Confidence: {result['confidence']}%")
        print(f"📝 Jumlah kata: {result['word_count']}")
        print(f"\n📄 Teks hasil ekstraksi:")
        print(f"{'-'*70}")
        print(result['text'])
        print(f"{'-'*70}")
    else:
        print(f"\n❌ Ekstraksi gagal!")
        print(f"Error: {result['error']}")
    
    return result


if __name__ == "__main__":
    # Contoh penggunaan
    print("OCR Utils Module untuk Scam Alert")
    print("Pastikan Tesseract OCR sudah terinstall!")
    print("\nCara install Tesseract:")
    print("  Windows: Download dari https://github.com/UB-Mannheim/tesseract/wiki")
    print("  Linux: sudo apt-get install tesseract-ocr tesseract-ocr-ind")
    print("  Mac: brew install tesseract tesseract-lang")