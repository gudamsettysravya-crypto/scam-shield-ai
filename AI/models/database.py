import sqlite3
import os
import json
from datetime import datetime
from config import Config

def get_db_connection():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Analysis Reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            scam_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            indicators_json TEXT NOT NULL,
            urls_json TEXT NOT NULL,
            safety_suggestions_json TEXT NOT NULL,
            next_steps_json TEXT NOT NULL,
            full_json TEXT NOT NULL,
            language TEXT DEFAULT 'en',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

# --- User Data Access Helpers ---

def create_user(full_name, email, password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
            (full_name, email.lower().strip(), password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email.lower().strip(),))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def update_user_name(user_id, full_name):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET full_name = ? WHERE id = ?', (full_name, user_id))
    conn.commit()
    conn.close()

def update_user_password(user_id, password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
    conn.commit()
    conn.close()

# --- Analysis Reports Data Access Helpers ---

def save_analysis(user_id, message_text, scam_type, risk_level, indicators, urls, safety_suggestions, next_steps, full_json, language='en'):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO analysis_reports (
            user_id, message_text, scam_type, risk_level, 
            indicators_json, urls_json, safety_suggestions_json, 
            next_steps_json, full_json, language
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        message_text,
        scam_type,
        risk_level,
        json.dumps(indicators) if isinstance(indicators, list) else indicators,
        json.dumps(urls) if isinstance(urls, list) else urls,
        json.dumps(safety_suggestions) if isinstance(safety_suggestions, list) else safety_suggestions,
        json.dumps(next_steps) if isinstance(next_steps, list) else next_steps,
        json.dumps(full_json) if isinstance(full_json, dict) else full_json,
        language
    ))
    conn.commit()
    report_id = cursor.lastrowid
    conn.close()
    return report_id

def get_user_analyses(user_id, limit=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = 'SELECT * FROM analysis_reports WHERE user_id = ? ORDER BY created_at DESC'
    if limit:
        query += f' LIMIT {int(limit)}'
    cursor.execute(query, (user_id,))
    reports = cursor.fetchall()
    conn.close()
    return reports

def get_analysis_by_id(analysis_id, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute('SELECT * FROM analysis_reports WHERE id = ? AND user_id = ?', (analysis_id, user_id))
    else:
        cursor.execute('SELECT * FROM analysis_reports WHERE id = ?', (analysis_id,))
    report = cursor.fetchone()
    conn.close()
    return report

def delete_analysis(analysis_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM analysis_reports WHERE id = ? AND user_id = ?', (analysis_id, user_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def get_user_dashboard_stats(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Counts by risk
    cursor.execute('SELECT COUNT(*) as total FROM analysis_reports WHERE user_id = ?', (user_id,))
    total = cursor.fetchone()['total'] or 0
    
    cursor.execute("SELECT COUNT(*) as cnt FROM analysis_reports WHERE user_id = ? AND UPPER(risk_level) = 'HIGH'", (user_id,))
    high = cursor.fetchone()['cnt'] or 0
    
    cursor.execute("SELECT COUNT(*) as cnt FROM analysis_reports WHERE user_id = ? AND UPPER(risk_level) = 'SUSPICIOUS'", (user_id,))
    suspicious = cursor.fetchone()['cnt'] or 0

    cursor.execute("SELECT COUNT(*) as cnt FROM analysis_reports WHERE user_id = ? AND UPPER(risk_level) = 'LOW'", (user_id,))
    low = cursor.fetchone()['cnt'] or 0
    
    # Scam type distribution
    cursor.execute('''
        SELECT scam_type, COUNT(*) as count 
        FROM analysis_reports 
        WHERE user_id = ? 
        GROUP BY scam_type 
        ORDER BY count DESC
    ''', (user_id,))
    types_rows = cursor.fetchall()
    scam_types = {row['scam_type']: row['count'] for row in types_rows}
    
    conn.close()
    return {
        'total': total,
        'high': high,
        'suspicious': suspicious,
        'low': low,
        'scam_types': scam_types
    }

def get_community_scam_trends():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT scam_type, COUNT(*) as count 
        FROM analysis_reports 
        GROUP BY scam_type 
        ORDER BY count DESC
    ''')
    rows = cursor.fetchall()
    
    total_analyses = sum(r['count'] for r in rows)
    most_frequent = rows[0]['scam_type'] if rows else 'None Yet'
    
    trends = {r['scam_type']: r['count'] for r in rows}
    conn.close()
    
    return {
        'total_community_analyses': total_analyses,
        'most_frequent': most_frequent,
        'trends': trends
    }

def seed_sample_data(user_id):
    """Seed dynamic sample analysis reports for demo if user has 0 records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as cnt FROM analysis_reports WHERE user_id = ?', (user_id,))
    count = cursor.fetchone()['cnt']
    if count == 0:
        samples = [
            (
                user_id,
                "Congratulations! You have won ₹50,000 in Tata Lottery. Pay ₹499 processing fee immediately to claim. Click http://tata-lottery-claim.xyz/reward",
                "Prize / Lottery Scam",
                "HIGH",
                json.dumps(["Unexpected prize claim", "Upfront payment request", "Creates urgency", "Suspicious TLD (.xyz)"]),
                json.dumps([{"url": "http://tata-lottery-claim.xyz/reward", "domain": "tata-lottery-claim.xyz", "observations": ["Uses HTTP instead of HTTPS", "Suspicious TLD .xyz", "Look-alike brand domain"]}]),
                json.dumps(["Do not pay the ₹499 fee.", "Do not click the link.", "Do not disclose bank details.", "Report Tata lottery impersonation to Tata Cyber Cell."]),
                json.dumps(["Preserve screenshot", "Block sender", "File complaint on cybercrime.gov.in"]),
                json.dumps({"risk_level": "HIGH", "scam_type": "Prize / Lottery Scam", "summary": "Urgent lottery prize demand requiring upfront fee."}),
                "en"
            ),
            (
                user_id,
                "Dear customer, your SBI NetBanking account will be blocked today due to pending KYC. Verify immediately at http://192.168.1.55/sbi/login.php or call 9876543210",
                "Banking Phishing",
                "HIGH",
                json.dumps(["Account suspension threat", "Urgent deadline", "IP address used as URL", "Requests credential verification"]),
                json.dumps([{"url": "http://192.168.1.55/sbi/login.php", "domain": "192.168.1.55", "observations": ["Raw IP address hostname", "Uses unencrypted HTTP", "Phishing path keywords"]}]),
                json.dumps(["Do not open the IP address link.", "Never enter netbanking password or OTP on external links.", "Contact SBI official helpline 1800-11-2211 directly."]),
                json.dumps(["Lock online access if credentials entered", "Report phishing link"]),
                json.dumps({"risk_level": "HIGH", "scam_type": "Banking Phishing", "summary": "Fake SBI KYC suspension threat using raw IP phishing page."}),
                "en"
            ),
            (
                user_id,
                "Part-time Job Offer! Earn ₹3000/day by liking YouTube videos. Telegram us @hr_easyjobs. Initial registration fee ₹200.",
                "Fake Job Scam",
                "HIGH",
                json.dumps(["Unrealistic salary for minimal effort", "Requests registration fee for employment", "Moves chat to Telegram"]),
                json.dumps([]),
                json.dumps(["Never pay to get a job.", "Legitimate employers never demand registration fees.", "Avoid recruiters refusing official email correspondence."]),
                json.dumps(["Block Telegram handle", "Do not transfer money"]),
                json.dumps({"risk_level": "HIGH", "scam_type": "Fake Job Scam", "summary": "Task-based YouTube video liking job requesting upfront registration fee."}),
                "en"
            ),
            (
                user_id,
                "Your OTP for SBI card transaction of Rs 4,500 is 884920. Do not share with anyone including bank staff.",
                "OTP Scam",
                "SUSPICIOUS",
                json.dumps(["Contains One Time Password (OTP)", "Alert message received without user initiated action"]),
                json.dumps([]),
                json.dumps(["Do not share this OTP with anyone calling or messaging you.", "If you did not initiate this transaction, contact SBI card support immediately to block your card."]),
                json.dumps(["Check account statement", "Lock card via official app"]),
                json.dumps({"risk_level": "SUSPICIOUS", "scam_type": "OTP Scam", "summary": "Unrequested transaction OTP alert."}),
                "en"
            ),
            (
                user_id,
                "Your Amazon order #402-9918231-1928312 has been dispatched. Track your delivery on official Amazon App.",
                "Shopping Scam",
                "LOW",
                json.dumps(["Standard transactional message", "No credential/payment request", "Refers to official app"]),
                json.dumps([]),
                json.dumps(["Message appears legitimate.", "Always check orders directly inside the official Amazon app."]),
                json.dumps(["Verify order history inside app"]),
                json.dumps({"risk_level": "LOW", "scam_type": "Shopping Scam", "summary": "Standard dispatch alert."}),
                "en"
            )
        ]
        cursor.executemany('''
            INSERT INTO analysis_reports (
                user_id, message_text, scam_type, risk_level, 
                indicators_json, urls_json, safety_suggestions_json, 
                next_steps_json, full_json, language
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', samples)
        conn.commit()
    conn.close()
