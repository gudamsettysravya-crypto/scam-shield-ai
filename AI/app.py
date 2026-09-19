import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

from config import Config
from models.database import (
    init_db, create_user, get_user_by_email, get_user_by_id,
    update_user_name, update_user_password, save_analysis,
    get_user_analyses, get_analysis_by_id, delete_analysis,
    get_user_dashboard_stats, get_community_scam_trends, seed_sample_data
)
from services.gemini_service import analyze_message_with_ai, ask_ai_safety_discussion
from services.ocr_service import extract_text_from_image
from services.report_service import generate_pdf_report
from services.url_analyzer import evaluate_single_url

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database schema on startup
with app.app_context():
    init_db()

# --- Login Required Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not full_name or not email or not password:
            flash('Please fill in all required fields.', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html')
            
        existing_user = get_user_by_email(email)
        if existing_user:
            flash('An account with this email already exists.', 'danger')
            return render_template('register.html')
            
        password_hash = generate_password_hash(password)
        user_id = create_user(full_name, email, password_hash)
        
        if user_id:
            session['user_id'] = user_id
            session['user_name'] = full_name
            # Seed demo data for new user dashboard
            seed_sample_data(user_id)
            flash('Registration successful! Welcome to SCAMSHIELD AI.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Registration failed. Please try again.', 'danger')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Please enter email and password.', 'danger')
            return render_template('login.html')
            
        user = get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['full_name']
            flash(f"Welcome back, {user['full_name']}!", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    # Seed demo data if zero records exist
    seed_sample_data(user_id)
    
    stats = get_user_dashboard_stats(user_id)
    recent_analyses = get_user_analyses(user_id, limit=5)
    trends = get_community_scam_trends()
    
    return render_template(
        'dashboard.html',
        stats=stats,
        recent_analyses=recent_analyses,
        trends=trends
    )

@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    if request.method == 'POST':
        user_id = session['user_id']
        message_text = request.form.get('message_text', '').strip()
        language = request.form.get('language', 'en')
        
        # Handle Screenshot Upload if provided
        if 'screenshot' in request.files and request.files['screenshot'].filename != '':
            file = request.files['screenshot']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                temp_path = os.path.join(Config.UPLOAD_FOLDER, filename)
                file.save(temp_path)
                
                # Perform OCR
                ocr_result = extract_text_from_image(temp_path)
                if ocr_result and ocr_result.get('extracted_text'):
                    if not message_text:
                        message_text = ocr_result['extracted_text']
                        
                # Clean up uploaded file for privacy
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
        
        if not message_text:
            flash('Please paste a suspicious message or upload a screenshot to analyze.', 'warning')
            return render_template('analyze.html')
            
        # Run AI Scam Analysis
        analysis_result = analyze_message_with_ai(message_text, language=language)
        
        # Save to database
        report_id = save_analysis(
            user_id=user_id,
            message_text=message_text,
            scam_type=analysis_result.get('scam_type', 'Other'),
            risk_level=analysis_result.get('risk_level', 'SUSPICIOUS'),
            indicators=analysis_result.get('indicators', []),
            urls=analysis_result.get('urls', []),
            safety_suggestions=analysis_result.get('safety_suggestions', []),
            next_steps=analysis_result.get('next_steps', []),
            full_json=analysis_result,
            language=language
        )
        
        return redirect(url_for('result', id=report_id))
        
    return render_template('analyze.html')

@app.route('/analyze/api_ocr', methods=['POST'])
@login_required
def api_ocr():
    """AJAX endpoint for instant text extraction from uploaded screenshot."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        temp_path = os.path.join(Config.UPLOAD_FOLDER, f"ocr_{filename}")
        file.save(temp_path)
        
        ocr_result = extract_text_from_image(temp_path)
        
        try:
            os.remove(temp_path)
        except Exception:
            pass
            
        return jsonify(ocr_result)
        
    return jsonify({'success': False, 'error': 'Invalid file format. Allowed: PNG, JPG, JPEG, WEBP'}), 400

@app.route('/result/<int:id>')
@login_required
def result(id):
    user_id = session['user_id']
    report = get_analysis_by_id(id, user_id=user_id)
    
    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Unpack JSON strings if needed
    try:
        indicators = json.loads(report['indicators_json']) if isinstance(report['indicators_json'], str) else report['indicators_json']
    except:
        indicators = [report['indicators_json']]
        
    try:
        urls = json.loads(report['urls_json']) if isinstance(report['urls_json'], str) else report['urls_json']
    except:
        urls = []
        
    try:
        suggestions = json.loads(report['safety_suggestions_json']) if isinstance(report['safety_suggestions_json'], str) else report['safety_suggestions_json']
    except:
        suggestions = [report['safety_suggestions_json']]

    try:
        next_steps = json.loads(report['next_steps_json']) if isinstance(report['next_steps_json'], str) else report['next_steps_json']
    except:
        next_steps = []

    # Extract AI summary/explanation from full_json
    summary = ''
    try:
        full = json.loads(report['full_json']) if isinstance(report['full_json'], str) else report['full_json']
        summary = full.get('summary', '')
        if not next_steps:
            next_steps = full.get('next_steps', [])
        if not suggestions:
            suggestions = full.get('safety_suggestions', [])
    except:
        summary = ''

    if not summary:
        risk = report['risk_level']
        stype = report['scam_type']
        summary = f"This communication was analyzed by ScamShield AI and classified as {risk} risk under {stype}. Linguistic markers, urgency triggers, and suspicious fraud indicators were evaluated to determine this threat profile."

    if not next_steps:
        next_steps = [
            "Do not click any links or download attachments from this message.",
            "Never disclose OTPs, UPI PINs, passwords, or banking credentials.",
            "Verify the communication independently through official published customer care numbers.",
            "Block and report the sender on your mobile device or messaging application.",
            "If any unauthorized transaction took place, immediately call 1930 and notify your bank."
        ]

    return render_template(
        'result.html',
        report=report,
        indicators=indicators,
        urls=urls,
        suggestions=suggestions,
        next_steps=next_steps,
        summary=summary
    )

@app.route('/reports')
@login_required
def reports():
    user_id = session['user_id']
    user_reports = get_user_analyses(user_id)
    return render_template('reports.html', reports=user_reports)

@app.route('/reports/download/<int:id>')
@login_required
def download_report(id):
    user_id = session['user_id']
    report = get_analysis_by_id(id, user_id=user_id)
    
    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('reports'))
        
    try:
        pdf_path = generate_pdf_report(report, user_name=session.get('user_name', 'User'))
        created_at_raw = report['created_at'] if hasattr(report, 'keys') and 'created_at' in report.keys() else '2026-09-18'
        clean_time = str(created_at_raw).replace(':', '-').replace(' ', '_')[:19]
        download_filename = f"ScamShield_AI_Report_{clean_time}_{id}.pdf"
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=download_filename,
            mimetype='application/pdf'
        )
    except Exception as e:
        flash(f"Could not generate PDF report: {e}", 'danger')
        return redirect(url_for('result', id=id))

@app.route('/reports/delete/<int:id>', methods=['POST'])
@login_required
def delete_report_route(id):
    user_id = session['user_id']
    success = delete_analysis(id, user_id)
    if success:
        flash('Analysis report deleted.', 'info')
    else:
        flash('Could not delete report.', 'danger')
    return redirect(url_for('reports'))

# --- Comprehensive Threat Protection Routes ---

@app.route('/threat-protection')
def threat_protection():
    return render_template('threat_protection/hub.html')

@app.route('/threat-protection/screenshot', methods=['GET', 'POST'])
def threat_screenshot():
    analysis = None
    analyzed_content = ""
    report_id = None
    
    if request.method == 'POST':
        message_text = request.form.get('message_text', '').strip()
        language = request.form.get('language', 'en')
        
        # Handle Screenshot Upload if provided
        if 'screenshot' in request.files and request.files['screenshot'].filename != '':
            file = request.files['screenshot']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                temp_path = os.path.join(Config.UPLOAD_FOLDER, f"scr_{filename}")
                file.save(temp_path)
                ocr_result = extract_text_from_image(temp_path)
                if ocr_result and ocr_result.get('extracted_text'):
                    if not message_text:
                        message_text = ocr_result['extracted_text']
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
                    
        if not message_text:
            flash('Please upload a screenshot or enter message text from a screenshot.', 'warning')
            return render_template('threat_protection/screenshot.html')
            
        analyzed_content = message_text
        analysis = analyze_message_with_ai(message_text, language=language)
        
        # Save to database if user session exists or using default demo user (id=1)
        target_user_id = session.get('user_id', 1)
        report_id = save_analysis(
            user_id=target_user_id,
            message_text=message_text,
            scam_type=analysis.get('scam_type', 'Screenshot Communication'),
            risk_level=analysis.get('risk_level', 'SUSPICIOUS'),
            indicators=analysis.get('indicators', []),
            urls=analysis.get('urls', []),
            safety_suggestions=analysis.get('safety_suggestions', []),
            next_steps=analysis.get('next_steps', []),
            full_json=analysis,
            language=language
        )

    return render_template(
        'threat_protection/screenshot.html',
        analysis=analysis,
        analyzed_content=analyzed_content,
        report_id=report_id
    )

@app.route('/threat-protection/ai-discussions')
def threat_discussion():
    return render_template('threat_protection/discussion.html')

@app.route('/threat-protection/api-discussion', methods=['POST'])
def api_discussion():
    data = request.get_json() or {}
    question = data.get('question', '').strip()
    language = data.get('language', 'en')
    if not question:
        return jsonify({'answer': 'Please provide a question about scam safety or fraud.'}), 400
    res = ask_ai_safety_discussion(question, language=language)
    return jsonify(res)

@app.route('/threat-protection/link-safety', methods=['GET', 'POST'])
def threat_link_safety():
    result = None
    analyzed_url = ""
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash('Please enter a web address / link to inspect.', 'warning')
            return render_template('threat_protection/link_safety.html')
        analyzed_url = url
        result = evaluate_single_url(url)
        
    return render_template('threat_protection/link_safety.html', result=result, analyzed_url=analyzed_url)

@app.route('/threat-protection/identity-protection')
def threat_identity():
    return render_template('threat_protection/identity.html')

@app.route('/threat-protection/incident-reports')
def threat_incidents():
    user_reports = []
    user_id = session.get('user_id', 1)
    user_reports = get_user_analyses(user_id, limit=5)
    return render_template('threat_protection/incidents.html', recent_reports=user_reports)

@app.route('/threat-protection/record-incident', methods=['POST'])
def threat_record_incident():
    scam_category = request.form.get('scam_category', 'Fraud Incident').strip()
    suspect_identifier = request.form.get('suspect_identifier', '').strip()
    incident_narrative = request.form.get('incident_narrative', '').strip()
    financial_loss = request.form.get('financial_loss', 'No')
    language = request.form.get('language', 'en')
    
    if not incident_narrative:
        flash('Please provide an incident description or message content.', 'warning')
        return redirect(url_for('threat_incidents'))
        
    composite_message = (
        f"[INCIDENT REPORT - {scam_category.upper()}]\n"
        f"Suspect Phone / ID / Link: {suspect_identifier}\n"
        f"Financial Loss Status: {financial_loss}\n\n"
        f"Incident Evidence & Details:\n{incident_narrative}"
    )
    
    analysis = analyze_message_with_ai(composite_message, language=language)
    user_id = session.get('user_id', 1)
    
    report_id = save_analysis(
        user_id=user_id,
        message_text=composite_message,
        scam_type=scam_category,
        risk_level=analysis.get('risk_level', 'HIGH'),
        indicators=analysis.get('indicators', []),
        urls=analysis.get('urls', []),
        safety_suggestions=analysis.get('safety_suggestions', []),
        next_steps=analysis.get('next_steps', []),
        full_json=analysis,
        language=language
    )
    
    flash('Incident report logged successfully! You can download your official PDF report below.', 'success')
    return redirect(url_for('result', id=report_id))

@app.route('/threat-protection/multi-tenant')
def threat_multitenant():
    return render_template('threat_protection/multitenant.html')

@app.route('/awareness')
def awareness():
    return render_template('awareness.html', scams=AWARENESS_DATA)

# --- Per-category scam awareness data ---
AWARENESS_DATA = {
    'prize-lottery': {
        'slug': 'prize-lottery',
        'image': 'scam_prize_lottery.jpg',
        'emoji': '🎁',
        'icon': 'fa-gift',
        'icon_color': 'text-danger',
        'title': 'Prize / Lottery Scams',
        'tagline': 'You did NOT win. Legitimate lotteries never ask for money to release winnings.',
        'description': (
            'Fraudsters send fake notifications claiming you won a massive lottery or prize reward. '
            'They deceive you into paying an advance "processing fee" or tax before vanishing.'
        ),
        'facts': [
            'Over ₹11,000 crore was lost by Indians to digital fraud in 2023, with fake lotteries ranking in the top 3.',
            'Legitimate lotteries or contests never demand upfront fees or taxes to release your prize money.',
            'Brands like KBC, Tata, or Amazon never contact winners through random personal WhatsApp numbers.'
        ],
        'fact': 'Over ₹11,000 crore was lost by Indians to digital fraud in 2023, with fake lotteries ranking in the top 3.',
        'examples': [
            '"Congratulations! Your mobile number won ₹25,00,000 in KBC WhatsApp Lucky Draw. Pay ₹499 fee to claim: http://kbc-draw.xyz"',
            '"Tata Motors Anniversary Draw: You won a brand new car! Call officer on 9876543210 to deposit dispatch registration charges."',
            '"Amazon Lucky Draw: You are selected for an iPhone 15 Pro. Pay ₹99 courier charges within 2 hours to receive delivery."'
        ],
        'warning_signs': [
            'You did not enter any official contest or purchase any lottery ticket',
            'Demands upfront payment (registration fee, government tax, processing charge)',
            'Creates extreme urgency: "Claim within 24 hours or prize will be forfeited"',
            'Sent from an ordinary 10-digit mobile number or unverified WhatsApp account',
            'Links redirect to suspicious domain extensions (.xyz, .top, .site)'
        ],
        'what_to_do': [
            'Never pay any amount — no matter how small — to receive a prize or lottery winnings.',
            'Do not click on links or share personal details like Aadhaar, PAN, or bank credentials.',
            'Block the suspicious sender immediately on phone or messaging applications.',
            'Report the fraud attempt to National Cyber Helpline at 1930 or cybercrime.gov.in.'
        ],
        'badge_color': 'danger',
    },
    'banking-phishing': {
        'slug': 'banking-phishing',
        'image': 'scam_banking_phishing.jpg',
        'emoji': '🏦',
        'icon': 'fa-landmark',
        'icon_color': 'text-warning',
        'title': 'Banking / Phishing Scams',
        'tagline': 'Your bank will NEVER ask for your OTP, PIN, password, or CVV.',
        'description': (
            'Scammers impersonate legitimate banks or payment services, sending urgent alerts about blocked accounts or expiring KYC. '
            'They trick victims into revealing confidential passwords, PINs, or OTPs through fake clone websites.'
        ),
        'facts': [
            'Phishing attacks account for over 70% of digital banking fraud complaints in India.',
            'Bank officials and RBI representatives are strictly forbidden from asking for your OTP or password.',
            'Your bank\'s genuine customer care number is always printed directly on the back of your card.'
        ],
        'fact': 'Phishing attacks account for over 70% of digital banking fraud complaints in India.',
        'examples': [
            '"SBI Alert: Your NetBanking account is blocked today due to pending KYC. Verify immediately at: http://192.168.1.55/sbi"',
            '"HDFC Bank Customer: Your debit card is suspended. Call 9876543210 or share OTP received on your phone to reactivate."',
            '"RBI Notification: Update your PAN details immediately to avoid deactivation. Visit: http://rbi-kyc-portal.online"'
        ],
        'warning_signs': [
            'Threatens immediate account suspension, deactivation, or card blocking',
            'Asks you to disclose your secret OTP, UPI PIN, CVV, or net-banking password',
            'Link contains raw IP address (e.g. http://192.168.x.x) or misspelled bank domain',
            'Arrives from an unverified 10-digit mobile number rather than a formal bank SMS header',
            'Caller pressures you to act immediately or download screen-sharing apps (AnyDesk)'
        ],
        'what_to_do': [
            'Never disclose your OTP, PIN, CVV, or passwords to anyone, even callers claiming to be bank staff.',
            'Never click links in SMS; always open your banking app directly or type the verified URL manually.',
            'If you accidentally shared credentials, call your bank immediately to freeze your account, then dial 1930.'
        ],
        'badge_color': 'warning',
    },
    'fake-job': {
        'slug': 'fake-job',
        'image': 'scam_fake_job.jpg',
        'emoji': '💼',
        'icon': 'fa-briefcase',
        'icon_color': 'text-info',
        'title': 'Fake Job Scams',
        'tagline': 'No legitimate employer will ever ask you to pay money to get hired.',
        'description': (
            'Fraudsters post lucrative part-time or work-from-home offers promising easy daily income for simple online tasks. '
            'After enticing victims, they demand upfront "registration fees", training charges, or prepaid investment tasks.'
        ),
        'facts': [
            'Over 40% of digital fraud complaints among young adults (18–30) involve fraudulent work-from-home schemes.',
            'Genuine companies and recruitment agencies never charge candidates any onboarding fee or security deposit.',
            'Recruitment conducted strictly via Telegram or WhatsApp channels is a hallmark of fraud operations.'
        ],
        'fact': 'Over 40% of digital fraud complaints among young adults (18–30) involve fraudulent work-from-home schemes.',
        'examples': [
            '"Part-time Work From Home: Earn ₹3,000 daily by liking YouTube videos. Telegram: @easy_tasks_2026. Pay ₹200 starter fee."',
            '"Amazon Data Entry Job: Flexible 2-hour daily shift paying ₹25,000/month. Pay ₹999 refundable deposit for credentials."',
            '"Freelance Product Reviewer: Complete prepaid review tasks to earn 30% commission instantly. Join our Telegram group."'
        ],
        'warning_signs': [
            'Promises unrealistically high daily income (₹2,000–₹5,000/day) for trivial tasks',
            'Demands upfront payment for "registration", "security deposit", or "training materials"',
            'Communication takes place exclusively via Telegram or WhatsApp without corporate email',
            'No formal interview, background check, or official offer letter from a verified company domain',
            'Asks you to deposit money into individual UPI accounts for prepaid tasks'
        ],
        'what_to_do': [
            'Never pay any money to secure employment, work materials, or portal access.',
            'Verify the company independently on official career portals, LinkedIn, and mca.gov.in.',
            'Immediately exit Telegram groups asking for prepaid task deposits or crypto purchases.'
        ],
        'badge_color': 'info',
    },
    'upi-payment': {
        'slug': 'upi-payment',
        'image': 'scam_upi_payment.jpg',
        'emoji': '💸',
        'icon': 'fa-indian-rupee-sign',
        'icon_color': 'text-success',
        'title': 'UPI / Payment Scams',
        'tagline': 'Scanning a QR code or entering your UPI PIN always DEBITS money from YOUR account.',
        'description': (
            'Scammers exploit digital payment apps by sending payment collect requests or malicious QR codes disguised as incoming funds. '
            'Scanning the code or entering your secret UPI PIN instantly transfers money out of your account to the fraudster.'
        ),
        'facts': [
            'Entering your UPI PIN ALWAYS transfers money out; you NEVER enter a PIN to receive money.',
            'UPI-related fraud rose by over 150% in recent years, driven primarily by the "QR code scan to receive" trick.',
            'Fake payment confirmation screenshots generated by spoof apps are widely used to cheat online sellers.'
        ],
        'fact': 'Entering your UPI PIN ALWAYS transfers money out; you NEVER enter a PIN to receive money.',
        'examples': [
            '"OLX Buyer: I have sent a ₹15,000 UPI QR code on WhatsApp. Scan it and enter your PIN to receive the advance payment."',
            '"PhonePe Customer Care: Your ₹850 refund is pending. Accept the incoming collect request in your app to credit funds."',
            '"Friend Emergency: Hi, my phone broke. Urgently send ₹3,000 via UPI to emergency@upi, will return first thing tomorrow."'
        ],
        'warning_signs': [
            'Stranger claims they are sending money and instructs you to "scan QR code and enter PIN to receive"',
            'A "Collect Request" notification appears in your UPI app for money you were supposed to get',
            'Caller claims to process an e-commerce refund and insists on remote desktop access or QR scanning',
            'Buyer sends a payment screenshot but the balance does not reflect in your bank account statement'
        ],
        'what_to_do': [
            'Remember: You NEVER need to enter your UPI PIN to receive money into your bank account.',
            'Never scan QR codes sent by strangers on WhatsApp, OLX, or social media platforms.',
            'Verify incoming payments directly in your bank statement, not by relying on chat screenshots.'
        ],
        'badge_color': 'success',
    },
    'romance': {
        'slug': 'romance',
        'image': 'scam_romance.jpg',
        'emoji': '💕',
        'icon': 'fa-heart',
        'icon_color': 'text-danger',
        'title': 'Romance Scams',
        'tagline': 'If an online stranger falls in love too quickly and asks for money — it is a scam.',
        'description': (
            'Fraudsters create fake romantic or matrimonial profiles to build intimate emotional trust over weeks or months. '
            'Once emotional leverage is established, they fabricate sudden crises demanding urgent financial transfers.'
        ),
        'facts': [
            'Romance scam victims in India suffer an average financial loss of ₹8 to 15 Lakh per incident.',
            'Fraudsters routinely use stolen photos of foreign models, military personnel, or doctors.',
            'The "customs gift parcel" trick is the single most common pretext used in matrimonial scams in India.'
        ],
        'fact': 'Romance scam victims in India suffer an average financial loss of ₹8 to 15 Lakh per incident.',
        'examples': [
            '"NRI Doctor on Matrimonial site: Professes deep love. After 1 month, requests ₹2 Lakh for a sudden medical crisis."',
            '"Instagram DM from foreign friend: Claims to have sent expensive jewelry stuck at customs; asks you to pay ₹25,000 clearance tax."',
            '"Military Officer on Facebook: Requests ₹50,000 for emergency leave flight tickets to visit India and meet you."'
        ],
        'warning_signs': [
            'Claims to be an NRI, foreign military officer, or overseas specialist making in-person meetings impossible',
            'Expresses intense love, emotional devotion, or marriage proposals unrealistically fast',
            'Consistently makes excuses to avoid live video calls or meeting face-to-face',
            'Fabricates sudden emergencies: hospital fees, travel costs, or customs duties on gifts',
            'Requests payments through wire transfers, cryptocurrency, gift cards, or third-party UPI IDs'
        ],
        'what_to_do': [
            'Never send money or share bank details with someone you have not met in person.',
            'Perform a reverse image search on profile pictures using Google Lens or TinEye.',
            'Discuss the relationship with trusted family members or friends before making any financial decisions.'
        ],
        'badge_color': 'danger',
    },
    'malicious-url': {
        'slug': 'malicious-url',
        'image': 'scam_malicious_url.jpg',
        'emoji': '🔗',
        'icon': 'fa-link',
        'icon_color': 'text-primary',
        'title': 'Malicious URL Scams',
        'tagline': 'Always inspect the full web address before you click on any link.',
        'description': (
            'Attackers craft deceptively structured links using misspelled domain names, URL shorteners, or unencrypted endpoints. '
            'Clicking these links exposes users to credential harvesting, malware downloads, or full device compromise.'
        ),
        'facts': [
            'Over 450,000 new malicious phishing domains are registered and weaponized globally every single day.',
            'Attackers heavily exploit cheap or free top-level domains (.xyz, .top, .online, .club) for phishing clones.',
            'HTTPS encrypts data in transit, but phishing sites also use free SSL certificates; always inspect the domain name.'
        ],
        'fact': 'Over 450,000 new malicious phishing domains are registered and weaponized globally every single day.',
        'examples': [
            '"http://sbi-secure-login.online/account-verify" — Look-alike domain impersonating SBI with suspicious .online TLD.',
            '"http://192.168.1.55/hdfc/kyc.php" — Raw IP address used to host an unencrypted banking credential theft page.',
            '"bit.ly/claim-tax-refund-now" — Shortened URL masking the true malicious phishing destination.'
        ],
        'warning_signs': [
            'Link uses unencrypted HTTP instead of HTTPS (no security padlock in browser)',
            'Domain is a raw numerical IP address (e.g. http://192.168.x.x/) instead of a verified name',
            'Uses high-risk top-level domain extensions (.xyz, .top, .online, .club, .site)',
            'URL shorteners used (bit.ly, tinyurl) to obscure the final destination address',
            'Domain name contains slight misspellings (e.g. paytm-update.com, amazom.in)'
        ],
        'what_to_do': [
            'Hover over links or inspect the full destination address before clicking.',
            'Type banking and payment website addresses directly into the browser rather than clicking links.',
            'Use ScamShield AI\'s Link Safety Analysis to evaluate suspicious URLs before opening them.'
        ],
        'badge_color': 'primary',
    },
}

@app.route('/awareness/<slug>')
def awareness_detail(slug):
    data = AWARENESS_DATA.get(slug)
    if not data:
        flash('Scam category not found.', 'warning')
        return redirect(url_for('awareness'))
    return render_template('awareness_detail.html', scam=data)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    stats = get_user_dashboard_stats(user_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_name':
            full_name = request.form.get('full_name', '').strip()
            if full_name:
                update_user_name(user_id, full_name)
                session['user_name'] = full_name
                flash('Profile name updated successfully.', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Name cannot be empty.', 'danger')
                
        elif action == 'change_password':
            old_pass = request.form.get('old_password', '')
            new_pass = request.form.get('new_password', '')
            confirm_pass = request.form.get('confirm_password', '')
            
            if not check_password_hash(user['password_hash'], old_pass):
                flash('Current password is incorrect.', 'danger')
            elif new_pass != confirm_pass:
                flash('New passwords do not match.', 'danger')
            elif len(new_pass) < 6:
                flash('New password must be at least 6 characters long.', 'danger')
            else:
                update_user_password(user_id, generate_password_hash(new_pass))
                flash('Password changed successfully.', 'success')
                return redirect(url_for('profile'))
                
    return render_template('profile.html', user=user, stats=stats)

# --- Error Handlers ---

@app.errorhandler(404)
def page_not_found(e):
    return render_template('index.html', error="Requested page not found."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('index.html', error="An internal server error occurred. Please try again."), 500

@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Maximum allowed file size is 16 MB.', 'danger')
    return redirect(url_for('analyze'))

if __name__ == '__main__':
    print("Starting SCAMSHIELD AI Flask Server on http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
