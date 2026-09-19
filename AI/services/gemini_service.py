import os
import json
import re
from config import Config
from services.url_analyzer import analyze_urls

# System prompt template for Gemini API
SYSTEM_PROMPT = """
You are SCAMSHIELD AI, an expert digital scam detection and cybersecurity risk assessment agent.
Analyze the user's message/communication for scam indicators, suspicious patterns, and potential fraud risks.

CRITICAL MANDATE:
Do NOT make a definitive legal or factual assertion that something IS or IS NOT a scam.
Provide a professional RISK ASSESSMENT with disclaimer language.

Target Output Language: {language_name} ({language_code})

Respond ONLY with valid JSON matching this exact structure:
{{
  "risk_level": "HIGH" | "SUSPICIOUS" | "LOW",
  "scam_type": "Payment / UPI Scam" | "Banking Phishing" | "Fake Job Scam" | "Prize / Lottery Scam" | "OTP Scam" | "Shopping Scam" | "Investment Scam" | "Loan Scam" | "Impersonation Scam" | "Social Engineering" | "Suspicious Link" | "Other" | "Unknown / Needs Verification",
  "confidence_note": "This is a risk assessment based on the information provided, not a definitive legal or factual determination.",
  "summary": "Concise summary of the communication analysis in {language_name}",
  "indicators": [
    "Detected indicator 1 in {language_name}",
    "Detected indicator 2 in {language_name}"
  ],
  "urgency_detected": true | false,
  "payment_request_detected": true | false,
  "credential_request_detected": true | false,
  "safety_suggestions": [
    "Actionable recommendation 1 in {language_name}",
    "Actionable recommendation 2 in {language_name}"
  ],
  "next_steps": [
    "Recommended next step 1 in {language_name}",
    "Recommended next step 2 in {language_name}"
  ]
}}
"""

LANGUAGE_MAP = {
    'en': 'English',
    'te': 'Telugu',
    'hi': 'Hindi'
}

def analyze_message_with_ai(message_text, language='en'):
    """
    Main AI analysis entrypoint using Gemini API with intelligent heuristic fallback.
    """
    if not message_text or not message_text.strip():
        return get_fallback_analysis("No text content provided.", language)

    # Clean text
    clean_text = message_text.strip()
    
    # Analyze URLs in python first
    url_analysis = analyze_urls(clean_text)
    
    api_key = Config.GEMINI_API_KEY
    if api_key and api_key != 'YOUR_GEMINI_API_KEY_HERE':
        try:
            from google import genai as google_genai
            client = google_genai.Client(api_key=api_key)

            lang_name = LANGUAGE_MAP.get(language, 'English')
            prompt = SYSTEM_PROMPT.format(language_name=lang_name, language_code=language)
            prompt += f"\n\nUSER MESSAGE TO ANALYZE:\n\"\"\"{clean_text}\"\"\""

            response = client.models.generate_content(
                model='gemini-3.6-flash',
                contents=prompt
            )
            if response and response.text:
                resp_text = response.text.strip()
                # Remove markdown wrapping if present
                if resp_text.startswith("```"):
                    resp_text = re.sub(r"^```(?:json)?\n?", "", resp_text)
                    resp_text = re.sub(r"\n?```$", "", resp_text)

                parsed_data = json.loads(resp_text)
                # Inject URL analysis
                parsed_data["urls"] = url_analysis.get("urls", [])
                parsed_data["url_summary"] = url_analysis.get("summary", "No URL detected.")
                return parsed_data
        except Exception as e:
            print(f"Gemini API analysis notice (switching to heuristic engine): {e}")

    # Fallback to high-quality local rule engine
    return get_fallback_analysis(clean_text, language, url_analysis)


def get_fallback_analysis(message_text, language='en', url_analysis=None):
    """
    High-accuracy, rule-based heuristic scam analyzer used as a resilient fallback.
    """
    if url_analysis is None:
        url_analysis = analyze_urls(message_text)
        
    text_lower = message_text.lower()
    
    indicators = []
    risk_score = 0
    
    urgency_keywords = ['immediately', 'urgent', 'today', '24 hours', 'blocked', 'suspended', 'expire', 'last chance', 'hurry', 'at once', 'అత్యవసరం', 'వెంటనే', 'तुरंत', 'अति आवश्यक']
    payment_keywords = ['pay', 'fee', 'charge', 'processing fee', 'deposit', 'upi', 'gpay', 'phonepe', 'paytm', 'transfer', '₹', 'rs.', 'rupees', 'డబ్బు', 'రూపాయలు', 'रुपये', 'भुगतान']
    credential_keywords = ['otp', 'pin', 'cvv', 'password', 'netbanking', 'kyc', 'bank details', 'card number', 'పాస్‌వర్డ్', 'పిన్', 'पासवर्ड', 'पिन']
    prize_keywords = ['lottery', 'winner', 'won', 'lucky draw', 'prize', 'gift', 'reward', '50,000', '1,000,000', 'రూపాయల బహుమతి', 'इनाम', 'लॉटरी']
    job_keywords = ['work from home', 'part time job', 'telegram', 'like youtube videos', 'daily income', 'registration fee', 'ఉద్యోగం', 'नौकरी']
    loan_keywords = ['instant loan', 'pre-approved loan', 'no documentation', 'low interest loan', 'అప్పు', 'ऋण']
    investment_keywords = ['guaranteed return', 'double your money', 'crypto investment', 'daily profit', 'పెట్టుబడి', 'निवेश']

    urgency_detected = any(k in text_lower for k in urgency_keywords)
    payment_detected = any(k in text_lower for k in payment_keywords)
    credential_detected = any(k in text_lower for k in credential_keywords)

    if urgency_detected:
        risk_score += 25
        indicators.append("Urgent or threatening language demanding immediate response")
        
    if payment_detected:
        risk_score += 30
        indicators.append("Upfront payment, registration fee, or transfer requested")
        
    if credential_detected:
        risk_score += 35
        indicators.append("Requests sensitive credentials, OTP, PIN, CVV, or banking details")

    if any(k in text_lower for k in prize_keywords):
        risk_score += 30
        indicators.append("Unexpected prize, lottery, or reward claim")

    if any(k in text_lower for k in job_keywords):
        risk_score += 25
        indicators.append("Unrealistic job offer requiring initial payment or informal messaging channel")

    if url_analysis.get("has_urls"):
        risk_score += 20
        indicators.append(f"Contains external web link ({url_analysis['url_count']} detected)")
        for u in url_analysis.get("urls", []):
            for obs in u.get("observations", []):
                if "HTTPS" in obs or "IP address" in obs or "shortener" in obs or "TLD" in obs:
                    risk_score += 15
                    indicators.append(f"Link Observation: {obs}")

    # Classification
    scam_type = "Other"
    if any(k in text_lower for k in prize_keywords) or ("won" in text_lower and payment_detected):
        scam_type = "Prize / Lottery Scam"
    elif credential_detected and ("bank" in text_lower or "kyc" in text_lower or "blocked" in text_lower or "sbi" in text_lower):
        scam_type = "Banking Phishing"
    elif "otp" in text_lower:
        scam_type = "OTP Scam"
    elif any(k in text_lower for k in job_keywords):
        scam_type = "Fake Job Scam"
    elif payment_detected or "upi" in text_lower or "gpay" in text_lower:
        scam_type = "Payment / UPI Scam"
    elif any(k in text_lower for k in loan_keywords):
        scam_type = "Loan Scam"
    elif any(k in text_lower for k in investment_keywords):
        scam_type = "Investment Scam"
    elif url_analysis.get("has_urls"):
        scam_type = "Suspicious Link"

    # Risk level determination
    if risk_score >= 55:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOW"
        if not indicators:
            indicators.append("No common high-risk indicators detected in text.")

    # Multilingual translation helpers for fallback output
    if language == 'te':
        summary = f"సందేశ విశ్లేషణ: ఈ సందేశంలో {risk_level} ప్రమాద స్థాయి మరియు {scam_type} లక్షణాలు గుర్తించబడ్డాయి."
        indicators_formatted = [
            "అత్యవసరంగా స్పందించమని ఒత్తిడి చేయడం లేదా బెదిరించడం",
            "ముందస్తు డబ్బు లేదా రిజిస్ట్రేషన్ రుసుము అడగడం",
            "అనుమానాస్పద లింక్ లేదా OTP/PIN వివరాలను కోరడం"
        ] if risk_level != "LOW" else ["సాధారణ సందేశం; ఎటువంటి అనుమానాస్పద అంశాలు కనుగొనబడలేదు."]
        safety_suggestions = [
            "ఎట్టి పరిస్థితుల్లోనూ డబ్బును బదిలీ చేయవద్దు.",
            "సందేశంలో ఉన్న లింక్‌లను క్లిక్ చేయవద్దు.",
            "మీ OTP, PIN లేదా బ్యాంకు వివరాలను ఎవరితోనూ పంచుకోకండి.",
            "సంబంధిత సంస్థ అధికారిక వెబ్‌సైట్ ద్వారా స్వతంత్రంగా సరిచూసుకోండి."
        ]
        next_steps = [
            "అనుమానాస్పద నంబర్‌ను బ్లాక్ చేయండి.",
            "బాధితులైతే cybercrime.gov.in లో ఫిర్యాదు చేయండి."
        ]
    elif language == 'hi':
        summary = f"संदेश विश्लेषण: इस संचार में {risk_level} जोखिम स्तर और {scam_type} के लक्षण पाए गए हैं।"
        indicators_formatted = [
            "तुरंत कार्रवाई करने का दबाव या धमकी भरा लहजा",
            "अग्रिम शुल्क या पैसे ट्रांसफर करने का अनुरोध",
            "ओटीपी, पिन या संवेदनशील बैंक विवरण की मांग"
        ] if risk_level != "LOW" else ["सामान्य संदेश; कोई संदिग्ध पैटर्न नहीं मिला।"]
        safety_suggestions = [
            "किसी भी स्थिति में पैसे न भेजें।",
            "संदिग्ध लिंक पर क्लिक न करें।",
            "अपना ओटीपी, पिन या पासवर्ड कभी साझा न करें।",
            "संबंधित संस्थान की आधिकारिक वेबसाइट से पुष्टि करें।"
        ]
        next_steps = [
            "संदिग्ध नंबर को ब्लॉक करें।",
            "cybercrime.gov.in पर रिपोर्ट दर्ज करें।"
        ]
    else:
        summary = f"Communication analysis indicates a {risk_level} risk level associated with {scam_type} patterns."
        indicators_formatted = indicators
        safety_suggestions = [
            "Do not send money or pay processing/registration fees.",
            "Do not click on external links provided in unverified messages.",
            "Never share OTP, PIN, CVV, passwords, or bank details.",
            "Independently verify the claim through the official website or verified support hotline."
        ]
        next_steps = [
            "Block the sender on your messaging platform.",
            "Preserve screenshots and transaction records.",
            "Report fraudulent activity on official cybercrime channels (e.g. cybercrime.gov.in)."
        ]

    return {
        "risk_level": risk_level,
        "scam_type": scam_type,
        "confidence_note": "This is a risk assessment based on the information provided, not a definitive legal or factual determination.",
        "summary": summary,
        "indicators": indicators_formatted,
        "urgency_detected": urgency_detected,
        "payment_request_detected": payment_detected,
        "credential_request_detected": credential_detected,
        "urls": url_analysis.get("urls", []),
        "url_summary": url_analysis.get("summary", "No URL detected."),
        "safety_suggestions": safety_suggestions,
        "next_steps": next_steps
    }


def ask_ai_safety_discussion(question_text, language='en'):
    """
    Handles user inquiries about fraud, scams, OTP safety, and digital defense.
    Uses Gemini API if available, backed by an extensive cybersecurity knowledge engine.
    """
    if not question_text or not question_text.strip():
        return {
            "answer": "Please ask a specific question regarding suspicious messages, scams, OTP safety, or online fraud.",
            "source": "system"
        }

    question = question_text.strip()
    api_key = Config.GEMINI_API_KEY
    lang_name = LANGUAGE_MAP.get(language, 'English')

    if api_key and api_key != 'YOUR_GEMINI_API_KEY_HERE':
        try:
            from google import genai as google_genai
            client = google_genai.Client(api_key=api_key)

            discussion_prompt = (
                f"You are SCAMSHIELD AI Discussion Agent, a trusted cybersecurity and fraud prevention expert. "
                f"Provide actionable, clear, and reassuring guidance in {lang_name} to this user's question:\n\n"
                f"USER QUESTION: {question}\n\n"
                f"Structure your answer with: "
                f"1. Direct assessment of the situation / risk "
                f"2. Crucial warning signs "
                f"3. Practical safety steps they must take right now "
                f"4. Official reporting helpline (Cyber Helpline 1930 / cybercrime.gov.in) if relevant."
            )

            response = client.models.generate_content(
                model='gemini-3.6-flash',
                contents=discussion_prompt
            )
            if response and response.text:
                return {
                    "answer": response.text.strip(),
                    "source": "gemini"
                }
        except Exception as e:
            print(f"Gemini Discussion notice (using fallback): {e}")

    # Comprehensive fallback cybersecurity knowledge engine
    q_lower = question.lower()
    if "otp" in q_lower or "one time password" in q_lower or "pin" in q_lower:
        answer = (
            "### 🛡️ OTP Safety Guidance:\n\n"
            "• **Golden Rule:** NEVER share your One-Time Password (OTP) or UPI PIN with anyone — including callers claiming to be from your bank, NPCI, RBI, or telecom provider.\n"
            "• **Why:** Legitimate banks and government organizations NEVER ask for your OTP over phone, SMS, or WhatsApp. An OTP is only used by YOU to authorize an action.\n"
            "• **What to watch out for:** Callers claiming your SIM card is expiring, electricity will be cut off, or KYC is pending and asking you to 'read out the code'.\n"
            "• **Immediate Action:** If you accidentally shared an OTP, contact your bank immediately to freeze your account and debit card, then report to the cyber helpline at **1930**."
        )
    elif "qr" in q_lower or "upi" in q_lower or "gpay" in q_lower or "phonepe" in q_lower or "paytm" in q_lower:
        answer = (
            "### 💸 UPI & QR Code Fraud Safety:\n\n"
            "• **Critical Fact:** You NEVER need to enter your UPI PIN or scan a QR code to RECEIVE money. Entering a PIN or scanning a code always DEBITS (deducts) money from your account.\n"
            "• **Common Scam:** Scammers on OLX or Facebook Marketplace send a QR code claiming 'Scan this to receive your advance payment'. Once scanned and PIN entered, your account is drained.\n"
            "• **Immediate Action:** Decline all collect requests from unknown persons. If money was debited without consent, report within 24 hours at **cybercrime.gov.in** or call **1930**."
        )
    elif "job" in q_lower or "part time" in q_lower or "telegram" in q_lower or "youtube" in q_lower:
        answer = (
            "### 💼 Fake Job Offer Scams:\n\n"
            "• **Key Rule:** Legitimate companies NEVER ask you to pay registration fees, security deposits, or purchase crypto tokens to get hired.\n"
            "• **Common Scenario:** You receive an SMS or WhatsApp offer to earn ₹2,000–₹5,000 per day by 'liking YouTube videos' or doing simple reviews. You are directed to a Telegram group and asked to make small 'prepaid task' payments.\n"
            "• **Immediate Action:** Immediately exit and report the Telegram/WhatsApp channel. Never pay to get paid."
        )
    elif "electricity" in q_lower or "bill" in q_lower or "power" in q_lower:
        answer = (
            "### ⚡ Electricity Bill Disconnection Scams:\n\n"
            "• **The Scam:** SMS warning: 'Dear customer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer at 98xxxxxxx.'\n"
            "• **Reality:** Power utility companies NEVER send warnings from personal 10-digit mobile numbers or demand urgent payments via unknown APK apps (like AnyDesk, TeamViewer).\n"
            "• **Immediate Action:** Pay utility bills ONLY through the official electricity board website or trusted apps (Google Pay, Paytm, electricity board portal). Never call the phone number in the SMS."
        )
    elif "lottery" in q_lower or "prize" in q_lower or "won" in q_lower or "kbc" in q_lower:
        answer = (
            "### 🎁 Lottery & Prize Scam Defense:\n\n"
            "• **Core Truth:** If you didn't buy a lottery ticket or enter an official contest, you DID NOT win. No legitimate lottery demands a processing fee or GST upfront to release prize money.\n"
            "• **Common Lures:** 'KBC Lucky Draw ₹25 Lakh Winner', 'Tata Motors Car Prize', 'Amazon Lucky Customer'.\n"
            "• **Immediate Action:** Ignore and delete the message. Do not pay any processing fee or share your bank account or Aadhaar details."
        )
    elif "link" in q_lower or "url" in q_lower or "website" in q_lower or "click" in q_lower:
        answer = (
            "### 🔗 Link & URL Safety Guidance:\n\n"
            "• **Inspection Tips:** Look closely at the domain name. Scammers use typo-squatted domains like `sbi-login.xyz` or `amazom-deals.online`.\n"
            "• **Shortened URLs:** Avoid clicking `bit.ly`, `tinyurl`, or raw IP links (e.g. `http://192.168.x.x`) sent from unknown numbers.\n"
            "• **Immediate Action:** Use ScamShield AI's Link Safety Analyzer before opening unknown links. If already clicked, do NOT enter credentials, close the window, and change your passwords."
        )
    elif "sextortion" in q_lower or "video call" in q_lower or "blackmail" in q_lower:
        answer = (
            "### 🛡️ Video Call Blackmail & Sextortion Support:\n\n"
            "• **What Happened:** Scammers record an intimate or compromised screen capture during a brief video call and threaten to send it to your friends or family unless you pay.\n"
            "• **Critical Advice:** DO NOT PAY ANY MONEY. Paying will only lead to more demands. Scammers rarely publish the videos once they realize they cannot extort you.\n"
            "• **Immediate Action:** Block the blackmailer across all platforms. Set your social media profiles to private. Call National Cyber Helpline **1930** immediately for guidance."
        )
    else:
        answer = (
            f"### 🛡️ ScamShield AI Digital Protection Guidance:\n\n"
            f"Regarding your query about **'{question}'**:\n\n"
            f"1. **Always Verify Independently:** Never trust contact details provided inside unsolicited SMS, WhatsApp messages, or emails. Look up official contact information on the organization's verified website.\n"
            f"2. **Watch for Urgency:** Fraudsters always create false panic (account blocking, legal action, immediate cutoff) to prevent you from thinking clearly.\n"
            f"3. **Zero Trust for Credentials:** Never disclose passwords, OTPs, CVVs, or UPI PINs to anyone.\n"
            f"4. **Need Help?** Call India's National Cybercrime Helpline at **1930** or visit **cybercrime.gov.in**."
        )

    return {
        "answer": answer,
        "source": "knowledge_engine"
    }

