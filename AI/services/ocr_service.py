import os
from PIL import Image
from config import Config

def extract_text_from_image(image_path):
    """
    Extracts text from uploaded screenshot using Gemini Multimodal Vision API or Pytesseract OCR.
    """
    extracted_text = ""
    method_used = "None"
    
    # Try 1: Gemini API Vision (Multimodal - most accurate OCR)
    api_key = Config.GEMINI_API_KEY
    if api_key and api_key != 'YOUR_GEMINI_API_KEY_HERE':
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            img = Image.open(image_path)
            prompt = "Extract all text present in this screenshot. Return ONLY the plain text content extracted from the image. Do not add commentary."
            
            response = model.generate_content([prompt, img])
            if response and response.text:
                extracted_text = response.text.strip()
                method_used = "Gemini AI Vision"
                return {
                    "success": True,
                    "extracted_text": extracted_text,
                    "method": method_used
                }
        except Exception as e:
            print(f"Gemini OCR fallback notice: {e}")
            
    # Try 2: Pytesseract OCR
    try:
        import pytesseract
        # Check default Windows tesseract paths if executable not in PATH
        possible_paths = [
            r'C:\Program Files\Tesseract-OCR\tesseract.exe',
            r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
            os.path.expanduser(r'~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe')
        ]
        for p in possible_paths:
            if os.path.exists(p):
                pytesseract.pytesseract.tesseract_cmd = p
                break
                
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        if text and len(text.strip()) > 3:
            extracted_text = text.strip()
            method_used = "Tesseract OCR"
            return {
                "success": True,
                "extracted_text": extracted_text,
                "method": method_used
            }
    except Exception as e:
        print(f"Pytesseract notice: {e}")

    # Fallback default response if text could not be extracted
    return {
        "success": False,
        "extracted_text": "Sample Scam Message: Congratulations! You have won ₹50,000 Tata Lottery. Pay ₹499 processing fee immediately to claim. Click http://tata-lottery-claim.xyz/reward",
        "method": "Default Sample Fallback",
        "error": "Could not automatically read text from image. Sample text loaded for demonstration. Please edit the text below."
    }
