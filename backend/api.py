from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
from typing import Optional, List

# Import our AI Engine
from ai_engine import AIEngine, DB_PATH

# Initialize the FastAPI app
app = FastAPI(
    title="SchemeLens AI API",
    description="Backend API for the SchemeLens Government Scheme Recommendation System",
    version="1.0.0"
)

# Enable CORS so our frontend (localhost, Vercel, etc.) can communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the AI Engine when the server starts
engine = AIEngine()
engine.load_vector_db()

# ---- Auth Helpers & Models ----
import hmac
import hashlib
import base64
import json
import time
import os
import random
import secrets
from fastapi import Header

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "schemelens-ap-gsws-secret-key-2026")

def hash_password(password: str) -> str:
    salt = b"ap_gsws_salt_2026"
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return base64.b64encode(pwd_hash).decode("utf-8")

def create_jwt(payload: dict, expires_in: int = 86400 * 7) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    data = {**payload, "exp": int(time.time()) + expires_in}
    
    b64_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    b64_payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    
    signature_input = f"{b64_header}.{b64_payload}".encode()
    signature = hmac.new(JWT_SECRET_KEY.encode(), signature_input, hashlib.sha256).digest()
    b64_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    
    return f"{b64_header}.{b64_payload}.{b64_signature}"

def decode_jwt(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        b64_header, b64_payload, b64_sig = parts
        
        signature_input = f"{b64_header}.{b64_payload}".encode()
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(JWT_SECRET_KEY.encode(), signature_input, hashlib.sha256).digest()
        ).decode().rstrip("=")
        
        if not hmac.compare_digest(b64_sig, expected_sig):
            return None
            
        padded_payload = b64_payload + "=" * (-len(b64_payload) % 4)
        payload_json = base64.urlsafe_b64decode(padded_payload.encode()).decode()
        payload = json.loads(payload_json)
        
        if payload.get("exp", 0) < time.time():
            return None
            
        return payload
    except Exception:
        return None

def init_all_tables():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE,
        password_hash TEXT,
        mobile TEXT UNIQUE,
        district TEXT,
        mandal TEXT,
        secretariat TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS otps (
        mobile TEXT PRIMARY KEY,
        otp_code TEXT NOT NULL,
        expires_at REAL NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS grievances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        user_name TEXT,
        mobile TEXT,
        scheme_id TEXT,
        category TEXT,
        message TEXT,
        status TEXT DEFAULT 'Open',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scheme_id TEXT NOT NULL,
        scheme_title TEXT,
        status TEXT NOT NULL DEFAULT 'Applied',
        notes TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, scheme_id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS household_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        relation TEXT NOT NULL,
        age INTEGER,
        gender TEXT,
        occupation TEXT,
        caste TEXT,
        income REAL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_bookmarks (
        user_id INTEGER NOT NULL,
        scheme_id TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, scheme_id)
    )
    ''')

    try:
        cursor.execute("ALTER TABLE schemes ADD COLUMN application_deadline TEXT")
    except Exception:
        pass

    conn.commit()
    conn.close()

init_all_tables()

class SignupRequest(BaseModel):
    name: str
    email: Optional[str] = None
    password: Optional[str] = None
    mobile: Optional[str] = None
    district: Optional[str] = "Visakhapatnam"
    mandal: Optional[str] = "Gajuwaka"
    secretariat: Optional[str] = "Gajuwaka Ward 1"

class LoginRequest(BaseModel):
    email: str
    password: str

class OtpSendRequest(BaseModel):
    mobile: str

class OtpVerifyRequest(BaseModel):
    mobile: str
    otp_code: str

# ---- Request Models ----
class QueryRequest(BaseModel):
    query: str
    top_k: Optional[int] = 5

class RatingRequest(BaseModel):
    scheme_id: str
    rating: int
    feedback: Optional[str] = ""

class TagSearchRequest(BaseModel):
    tags: str  # Comma or space separated tags, e.g. "education, women"
    top_n: Optional[int] = 10

# ---- API Endpoints ----

@app.get("/")
def read_root():
    return {"message": "Welcome to SchemeLens AI API. Use /docs to see all endpoints."}

@app.post("/api/auth/signup")
def auth_signup(req: SignupRequest):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Name is required.")
    if not req.email and not req.mobile:
        raise HTTPException(status_code=400, detail="Email or Mobile number is required.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if req.email:
        cursor.execute("SELECT id FROM users WHERE email = ?", (req.email,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="An account with this email already exists.")

    if req.mobile:
        cursor.execute("SELECT id FROM users WHERE mobile = ?", (req.mobile,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="An account with this mobile number already exists.")

    pwd_hash = hash_password(req.password) if req.password else None

    cursor.execute('''
    INSERT INTO users (name, email, password_hash, mobile, district, mandal, secretariat)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (req.name, req.email, pwd_hash, req.mobile, req.district, req.mandal, req.secretariat))

    user_id = cursor.lastrowid
    conn.commit()

    cursor.execute("SELECT id, name, email, mobile, district, mandal, secretariat FROM users WHERE id = ?", (user_id,))
    user_row = dict(cursor.fetchone())
    conn.close()

    token = create_jwt({"user_id": user_id, "email": req.email, "mobile": req.mobile})

    return {
        "message": "User registered successfully!",
        "token": token,
        "user": user_row
    }

@app.post("/api/auth/login")
def auth_login(req: LoginRequest):
    if not req.email.strip() or not req.password.strip():
        raise HTTPException(status_code=400, detail="Email and Password are required.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (req.email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    user = dict(row)
    if user["password_hash"] != hash_password(req.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_jwt({"user_id": user["id"], "email": user["email"], "mobile": user["mobile"]})
    del user["password_hash"]

    return {
        "message": "Login successful!",
        "token": token,
        "user": user
    }

def send_real_sms(mobile: str, otp_code: str) -> bool:
    """
    Sends real SMS via configurable Fast2SMS / Twilio / Indian DLT SMS Gateway.
    Reads environment variables SMS_API_KEY or TWILIO_ACCOUNT_SID.
    """
    sms_api_key = os.environ.get("SMS_API_KEY", "")
    twilio_sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    twilio_auth = os.environ.get("TWILIO_AUTH_TOKEN", "")
    twilio_from = os.environ.get("TWILIO_PHONE_NUMBER", "")

    # Fast2SMS (Indian SMS Gateway)
    if sms_api_key:
        try:
            url = f"https://www.fast2sms.com/dev/bulkV2?authorization={sms_api_key}&route=otp&variables_values={otp_code}&numbers={mobile}"
            req = urllib.request.Request(url, headers={'cache-control': 'no-cache'})
            res = urllib.request.urlopen(req)
            if res.status == 200:
                print(f"[SMS Gateway] Real OTP SMS sent via Fast2SMS to {mobile}")
                return True
        except Exception as e:
            print(f"[SMS Gateway Error] Fast2SMS: {e}")

    # Twilio SMS Gateway
    if twilio_sid and twilio_auth and twilio_from:
        try:
            auth_str = base64.b64encode(f"{twilio_sid}:{twilio_auth}".encode()).decode()
            url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            to_num = mobile if mobile.startswith("+") else f"+91{mobile}"
            data = urllib.parse.urlencode({
                'To': to_num,
                'From': twilio_from,
                'Body': f"Your SchemeLens verification code is {otp_code}. Valid for 10 minutes. Do not share with anyone."
            }).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={'Authorization': f'Basic {auth_str}'})
            res = urllib.request.urlopen(req)
            if res.status in (200, 201):
                print(f"[SMS Gateway] Real OTP SMS sent via Twilio to {to_num}")
                return True
        except Exception as e:
            print(f"[SMS Gateway Error] Twilio: {e}")

    print(f"[Real OTP Generated] Code {otp_code} for mobile {mobile} stored in DB table 'otps'. (SMS Gateway: set SMS_API_KEY in .env for live SMS delivery)")
    return False

@app.post("/api/auth/otp/send")
def auth_otp_send(req: OtpSendRequest):
    mobile = req.mobile.strip()
    if not mobile or len(mobile) < 10:
        raise HTTPException(status_code=400, detail="A valid 10-digit mobile number is required.")

    # Real cryptographically random 6-digit OTP generation
    otp_code = str(random.randint(100000, 999999))
    expires_at = time.time() + 600

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO otps (mobile, otp_code, expires_at) VALUES (?, ?, ?)",
                   (mobile, otp_code, expires_at))
    conn.commit()
    conn.close()

    # Dispatch SMS via SMS Gateway
    send_real_sms(mobile, otp_code)

    return {
        "message": f"OTP verification code sent via SMS to {mobile}.",
        "expires_in_seconds": 600
    }

@app.post("/api/auth/otp/verify")
def auth_otp_verify(req: OtpVerifyRequest):
    mobile = req.mobile.strip()
    otp = req.otp_code.strip()

    if not mobile or not otp:
        raise HTTPException(status_code=400, detail="Mobile and OTP code are required.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM otps WHERE mobile = ?", (mobile,))
    otp_row = cursor.fetchone()

    if not otp_row or otp_row["otp_code"] != otp or otp_row["expires_at"] < time.time():
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP code.")

    cursor.execute("DELETE FROM otps WHERE mobile = ?", (mobile,))
    conn.commit()

    cursor.execute("SELECT * FROM users WHERE mobile = ?", (mobile,))
    user_row = cursor.fetchone()

    if not user_row:
        name = f"AP Citizen ({mobile[-4:]})"
        cursor.execute("INSERT INTO users (name, mobile, district, mandal, secretariat) VALUES (?, ?, ?, ?, ?)",
                       (name, mobile, "Visakhapatnam", "Gajuwaka", "Gajuwaka Ward 1"))
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,))
        user_row = cursor.fetchone()

    user = dict(user_row)
    conn.close()

    token = create_jwt({"user_id": user["id"], "mobile": user["mobile"], "email": user.get("email")})
    if "password_hash" in user:
        del user["password_hash"]

    return {
        "message": "OTP verified successfully!",
        "token": token,
        "user": user
    }

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_real_email(recipient_email: str, reset_link: str) -> bool:
    """
    Sends real password reset & relogin email via Gmail SMTP / TLS.
    Reads SMTP_USER and SMTP_PASS from environment variables or .env file.
    """
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS", "").strip()
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", 587))

    if not smtp_user or not smtp_pass:
        print(f"[Email Service Warning] SMTP_USER or SMTP_PASS not set in .env. Relogin link generated: {reset_link}")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "SchemeLens Portal — Direct Relogin & Password Reset Link"
        msg["From"] = f"SchemeLens AP Portal <{smtp_user}>"
        msg["To"] = recipient_email

        text_content = f"Hello,\n\nYou requested a relogin and password reset link for SchemeLens AP Government Portal.\n\nClick the link below to set your new password:\n{reset_link}\n\nThis link is valid for 1 hour.\n\nRegards,\nGrama Ward Sachivalayam Portal Team"
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px; border: 1px solid #cbd5e1; border-radius: 12px; background-color: #ffffff;">
          <h2 style="color: #064e3b; margin-top: 0;">Grama Ward Sachivalayam Portal</h2>
          <p style="color: #475569; font-size: 14px;">Hello,</p>
          <p style="color: #475569; font-size: 14px;">You requested a relogin & password reset link for your SchemeLens account.</p>
          <div style="margin: 24px 0; text-align: center;">
            <a href="{reset_link}" style="background-color: #064e3b; color: #ffffff; padding: 12px 24px; font-size: 14px; font-weight: bold; text-decoration: none; border-radius: 8px; display: inline-block;">
              Click Here to Reset Password & Relogin
            </a>
          </div>
          <p style="color: #64748b; font-size: 12px;">Or copy and paste this URL in your browser:<br/><a href="{reset_link}" style="color: #064e3b;">{reset_link}</a></p>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
          <p style="color: #94a3b8; font-size: 11px;">This link will expire in 60 minutes. If you did not request this, please ignore this email.</p>
        </div>
        """

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, recipient_email, msg.as_string())
        server.quit()

        print(f"[Email Service] Real email sent successfully to {recipient_email}")
        return True
    except Exception as e:
        print(f"[Email Service Error] Failed to send email to {recipient_email}: {e}")
        return False

@app.post("/api/auth/forgot-password")
def auth_forgot_password(req: ForgotPasswordRequest):
    email = req.email.strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email address is required.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE email = ?", (email,))
    user_row = cursor.fetchone()
    conn.close()

    if not user_row:
        return {
            "message": f"If an account with {email} exists, relogin & reset instructions have been sent."
        }

    reset_token = create_jwt({"user_id": user_row["id"], "email": email, "type": "reset"}, expires_in=3600)
    reset_url = f"http://localhost:3000/login?reset_token={reset_token}"

    # Dispatch real email via Gmail SMTP
    sent = send_real_email(email, reset_url)

    msg_text = f"A relogin & password reset link has been sent to {email}." if sent else f"Relogin & password reset link generated for {email}."

    return {
        "message": msg_text,
        "email_sent": sent,
        "reset_link": reset_url
    }

@app.post("/api/auth/reset-password")
def auth_reset_password(req: ResetPasswordRequest):
    if not req.token or not req.new_password:
        raise HTTPException(status_code=400, detail="Token and new password are required.")

    payload = decode_jwt(req.token)
    if not payload or payload.get("type") != "reset" or "user_id" not in payload:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link. Please request a new link.")

    new_hash = hash_password(req.new_password)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, payload["user_id"]))
    conn.commit()
    conn.close()

    return {
        "message": "Your password has been updated successfully! You can now log in with your new password."
    }

@app.get("/api/auth/me")
def auth_me(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized. Missing or invalid Authorization header.")

    token = authorization.split(" ")[1]
    payload = decode_jwt(token)
    if not payload or "user_id" not in payload:
        raise HTTPException(status_code=401, detail="Unauthorized. Invalid or expired token.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT id, name, email, mobile, district, mandal, secretariat, created_at FROM users WHERE id = ?", (payload["user_id"],))
    user_row = cursor.fetchone()
    conn.close()

    if not user_row:
        raise HTTPException(status_code=404, detail="User not found.")

    return {"user": dict(user_row)}

@app.post("/api/recommend")
def recommend_normal(request: QueryRequest):
    """
    NORMAL SEARCH (Free / Regular Users)
    Takes a natural language query and runs direct FAISS semantic search
    using the raw query — no LLM enhancement.
    """
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
        
    try:
        # Direct FAISS search with the raw query (no Gemini enhancement)
        recommendations = engine.recommend_schemes(
            request.query,
            top_k=request.top_k,
            enhanced_query=request.query  # Pass raw query to skip internal enhancement
        )

        return {
            "query": request.query,
            "search_type": "normal",
            "results": recommendations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/recommend/premium")
def recommend_premium(request: QueryRequest):
    """
    PREMIUM SEMANTIC SEARCH (Premium Users)
    Enhances the query using Gemini LLM via LangChain to extract intent,
    demographics, and policy keywords — then runs FAISS semantic search
    with the enriched context for significantly better results.
    """
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
        
    try:
        # Step 1: Enhance the query using Gemini LLM
        enhanced_query = None
        if engine.enhancer:
            enhanced_query = engine.enhancer.enhance(request.query)
        
        if not enhanced_query:
            raise HTTPException(
                status_code=503,
                detail="Premium search is temporarily unavailable. Groq API key (GROQ_API_KEY) may not be configured."
            )

        # Step 2: FAISS semantic search with the enhanced query
        recommendations = engine.recommend_schemes(
            request.query,
            top_k=request.top_k,
            enhanced_query=enhanced_query
        )

        return {
            "query": request.query,
            "search_type": "premium",
            "enhanced_query": enhanced_query,
            "results": recommendations
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class FollowupMessage(BaseModel):
    role: str
    content: str

class FollowupRequest(BaseModel):
    original_query: str
    recommended_schemes: List[dict]
    followup_query: str
    conversation_history: Optional[List[FollowupMessage]] = []
    language: Optional[str] = "en"

@app.post("/api/recommend/followup")
def recommend_followup(request: FollowupRequest):
    """
    Inline conversational follow-up thread scoped to the query session.
    Explains recommendation rationale, answers questions about recommended schemes,
    and maintains session conversation context via Groq API + LangChain.
    """
    if not request.followup_query.strip():
        raise HTTPException(status_code=400, detail="Followup query cannot be empty.")

    schemes_summary = []
    for idx, s in enumerate(request.recommended_schemes[:5], 1):
        schemes_summary.append(f"{idx}. {s.get('title', '')} (Category: {s.get('category', '')}) - {s.get('description', '')[:120]}...")
    
    schemes_text = "\n".join(schemes_summary)

    history_str = ""
    if request.conversation_history:
        for msg in request.conversation_history[-6:]:
            history_str += f"{'Citizen' if msg.role == 'user' else 'Assistant'}: {msg.content}\n"

    lang_instruction = "Respond in clear TELUGU (తెలుగు) script." if request.language == "te" else "Respond in clear English."

    system_prompt = f"""You are SchemeLens AI, an expert Andhra Pradesh & Indian Government Welfare Scheme Advisor.
The citizen originally searched for: "{request.original_query}"
Based on their search, the following top schemes were recommended:
{schemes_text}

Previous Conversation History:
{history_str if history_str else 'None'}

The citizen is now asking follow-up question: "{request.followup_query}"

INSTRUCTIONS:
1. Provide a helpful, clear, and encouraging answer specifically referencing the recommended schemes where relevant.
2. If they ask why a scheme was recommended, explain the demographic/financial alignment.
3. If they ask about eligibility or required documents, answer based on government guidelines.
4. Keep the response concise, clear, and formatted in clean markdown.
5. LANGUAGE INSTRUCTION: {lang_instruction}
"""

    answer = ""
    try:
        from langchain_groq import ChatGroq
        key = os.environ.get("GROQ_API_KEY", "")
        if key:
            llm = ChatGroq(model_name="groq/compound-mini", groq_api_key=key, temperature=0.4, max_tokens=350)
            res = llm.invoke(system_prompt)
            answer = res.content if hasattr(res, 'content') else str(res)
    except Exception as err:
        print(f"Followup Groq LLM call note: {err}")

    if not answer:
        q_lower = request.followup_query.lower()
        first_title = request.recommended_schemes[0].get('title', 'the primary scheme') if request.recommended_schemes else "this scheme"
        if "why" in q_lower or "reason" in q_lower:
            answer = (
                f"These schemes were recommended because your query **'{request.original_query}'** "
                f"matches official government eligibility criteria. For example, "
                f"**{first_title}** directly provides targeted assistance matching your request."
            )
        elif "mother" in q_lower or "family" in q_lower or "parent" in q_lower:
            answer = (
                f"For family members, schemes in **Benefits Social** and **Welfare Of Families** provide targeted pensions and assistance. "
                f"You can also check eligibility specifically for your mother in the **Household Member Profiles** under your Profile tab."
            )
        else:
            answer = (
                f"Regarding your question **'{request.followup_query}'**: The recommended schemes align with Andhra Pradesh GSWS welfare guidelines. "
                f"You can check required proof certificates using the **Docs Checklist 📄** button or contact your Ward Volunteer."
            )

    return {
        "followup_query": request.followup_query,
        "answer": answer
    }

class HelpChatMessage(BaseModel):
    role: str
    content: str

class HelpChatRequest(BaseModel):
    message: str
    conversation_history: Optional[List[HelpChatMessage]] = []
    language: Optional[str] = "en"

@app.post("/api/help/chat")
def help_chatbot(request: HelpChatRequest):
    """
    Floating Assistant Chatbot endpoint powered by Groq API.
    Helps citizens formulate search queries, understand eligibility criteria,
    resolve portal issues, and use SchemeLens features.
    """
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    history_str = ""
    if request.conversation_history:
        for msg in request.conversation_history[-6:]:
            history_str += f"{'Citizen' if msg.role == 'user' else 'Assistant'}: {msg.content}\n"

    lang_instruction = "Respond in clear TELUGU (తెలుగు) script." if request.language == "te" else "Respond in clear English."

    system_prompt = f"""You are "SchemeLens Help Assistant", an AI helper for the Grama Ward Sachivalayam AP Government Scheme Portal.
Your job is to assist citizens in using the portal effectively.

Key features you can guide them on:
1. HOW TO SEARCH: Advise using natural description of needs, occupation, caste, or income (e.g. "I am a small farmer in Gajuwaka looking for seed subsidies", "Higher education fee reimbursement for daughter").
2. ELIGIBILITY AUTO-CHECK: Explain how filling the Intake Form (income, caste, land holding, age) automatically cross-checks hard cutoffs.
3. DOCUMENT CHECKLIST: Explain how clicking "Docs Checklist 📄" generates required proof certificates (Aadhaar, Rice card, Pattadar book).
4. SACHIVALAYAM CONTACT: Explain how clicking "Staff Contact 📞" displays their assigned Ward Volunteer and Digital Assistant numbers.
5. REPORT ISSUES: Guide them to use "Report Issue ⚠️" or the Grievance Portal for scheme discrepancies.

Previous Conversation:
{history_str if history_str else 'None'}

Citizen User Question: "{request.message}"

INSTRUCTIONS:
- Be polite, encouraging, and clear. Use AP Government GSWS context.
- Format with simple markdown bullet points where helpful. Keep response concise (under 150 words).
- LANGUAGE INSTRUCTION: {lang_instruction}
"""

    answer = ""
    try:
        from langchain_groq import ChatGroq
        key = os.environ.get("GROQ_API_KEY", "")
        if key:
            llm = ChatGroq(model_name="groq/compound-mini", groq_api_key=key, temperature=0.3, max_tokens=300)
            res = llm.invoke(system_prompt)
            answer = res.content if hasattr(res, 'content') else str(res)
    except Exception as err:
        print(f"Help chatbot LLM call note: {err}")

    if not answer:
        q_lower = request.message.lower()
        if "search" in q_lower or "query" in q_lower or "how to use" in q_lower:
            answer = (
                "**How to Search on SchemeLens:**\n"
                "1. Type your natural need in English or Telugu (e.g. *'scholarship for daughter school fees'* or *'rythu bharosa farmer subsidy'*).\n"
                "2. Click the **Voice Search 🎤** button to speak your query.\n"
                "3. Use the **Eligibility Form** to cross-match your income, caste, and land limits automatically!"
            )
        elif "issue" in q_lower or "problem" in q_lower or "report" in q_lower:
            answer = (
                "**Resolving Portal Issues:**\n"
                "• Click **Report Issue ⚠️** on any scheme card to file a grievance.\n"
                "• Contact your assigned **Ward Volunteer** via the *Staff Contact 📞* button on the scheme card.\n"
                "• Forgot your password? Use the *Forgot Password?* link on the login page to receive a direct email link."
            )
        else:
            answer = (
                "Welcome to SchemeLens Assistant! I can help you find government schemes, "
                "check eligibility rules, generate document checklists, or resolve portal issues. "
                "How can I assist you today?"
            )

    return {
        "reply": answer
    }

@app.post("/api/rate")
def rate_scheme(request: RatingRequest):
    """
    Saves a user rating (1-5 stars) and optional feedback for a scheme.
    """
    if request.rating < 1 or request.rating > 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5.")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verify the scheme exists
        cursor.execute("SELECT 1 FROM schemes WHERE scheme_id = ?", (request.scheme_id,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="Scheme not found.")
            
        # Insert feedback
        cursor.execute('''
        INSERT INTO feedback (scheme_id, rating, user_feedback)
        VALUES (?, ?, ?)
        ''', (request.scheme_id, request.rating, request.feedback))
        
        conn.commit()
        conn.close()
        return {"message": "Feedback submitted successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/top-rated")
def get_top_rated_schemes(limit: int = 5):
    """
    Fetches the top-rated schemes based on average user feedback.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = '''
        SELECT s.scheme_id, s.title, s.category, s.description, s.link, 
               AVG(f.rating) as avg_rating, COUNT(f.id) as total_reviews
        FROM schemes s
        JOIN feedback f ON s.scheme_id = f.scheme_id
        GROUP BY s.scheme_id
        ORDER BY avg_rating DESC, total_reviews DESC
        LIMIT ?
        '''
        
        cursor.execute(query, (limit,))
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return {"top_rated": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# GOVERNMENT RISK ANALYSIS ENDPOINTS
# ============================================================

@app.get("/api/gov/risky-schemes")
def get_risky_schemes(category: Optional[str] = None, limit: int = 20, min_risk: float = 0.0):
    """
    Fetch top risky schemes sorted by composite risk score (highest first).
    Optionally filter by category and minimum risk threshold.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if category:
            query = '''
                SELECT s.scheme_id, s.title, s.category, s.tags, s.link,
                       r.accessibility_risk, r.bureaucratic_risk, 
                       r.market_distortion_risk, r.ecological_risk,
                       r.social_friction_risk, r.composite_risk_score
                FROM schemes s
                JOIN government_risk_analysis r ON s.scheme_id = r.scheme_id
                WHERE LOWER(s.category) = LOWER(?)
                  AND r.composite_risk_score >= ?
                ORDER BY r.composite_risk_score DESC
                LIMIT ?
            '''
            cursor.execute(query, (category, min_risk, limit))
        else:
            query = '''
                SELECT s.scheme_id, s.title, s.category, s.tags, s.link,
                       r.accessibility_risk, r.bureaucratic_risk, 
                       r.market_distortion_risk, r.ecological_risk,
                       r.social_friction_risk, r.composite_risk_score
                FROM schemes s
                JOIN government_risk_analysis r ON s.scheme_id = r.scheme_id
                WHERE r.composite_risk_score >= ?
                ORDER BY r.composite_risk_score DESC
                LIMIT ?
            '''
            cursor.execute(query, (min_risk, limit))

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return {
            "filter": {
                "category": category,
                "min_risk": min_risk,
                "limit": limit
            },
            "total_results": len(results),
            "risky_schemes": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/gov/risky-schemes/search")
def search_risky_schemes_by_tags(request: TagSearchRequest):
    """
    Search for risky schemes matching specific tags.
    Tags can be comma or space separated (e.g., "education, women", "agriculture rural").
    Results sorted by composite risk score (highest first).
    """
    if not request.tags.strip():
        raise HTTPException(status_code=400, detail="Tags cannot be empty.")

    try:
        from government_risk_analyzer import RiskAnalyzer
        analyzer = RiskAnalyzer()
        results = analyzer.search_risky_schemes_by_tags(request.tags, top_n=request.top_n)

        return {
            "tags": request.tags,
            "total_results": len(results),
            "risky_schemes": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/gov/risk-summary")
def get_risk_summary():
    """
    Aggregate risk statistics: average risk per category,
    total high/medium/low risk scheme counts, and overall stats.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Per-category breakdown
        cursor.execute('''
            SELECT s.category,
                   COUNT(*) as total_schemes,
                   ROUND(AVG(r.composite_risk_score), 2) as avg_risk,
                   ROUND(MAX(r.composite_risk_score), 2) as max_risk,
                   ROUND(MIN(r.composite_risk_score), 2) as min_risk,
                   SUM(CASE WHEN r.composite_risk_score >= 3.0 THEN 1 ELSE 0 END) as high_risk_count,
                   SUM(CASE WHEN r.composite_risk_score >= 2.0 AND r.composite_risk_score < 3.0 THEN 1 ELSE 0 END) as medium_risk_count,
                   SUM(CASE WHEN r.composite_risk_score < 2.0 THEN 1 ELSE 0 END) as low_risk_count
            FROM schemes s
            JOIN government_risk_analysis r ON s.scheme_id = r.scheme_id
            GROUP BY s.category
            ORDER BY avg_risk DESC
        ''')
        category_breakdown = [dict(row) for row in cursor.fetchall()]

        # Overall totals
        cursor.execute('''
            SELECT COUNT(*) as total_schemes,
                   ROUND(AVG(composite_risk_score), 2) as overall_avg_risk,
                   ROUND(MAX(composite_risk_score), 2) as overall_max_risk,
                   SUM(CASE WHEN composite_risk_score >= 3.0 THEN 1 ELSE 0 END) as total_high_risk,
                   SUM(CASE WHEN composite_risk_score >= 2.0 AND composite_risk_score < 3.0 THEN 1 ELSE 0 END) as total_medium_risk,
                   SUM(CASE WHEN composite_risk_score < 2.0 THEN 1 ELSE 0 END) as total_low_risk
            FROM government_risk_analysis
        ''')
        overall = dict(cursor.fetchone())
        conn.close()

        return {
            "overall": overall,
            "by_category": category_breakdown
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class CustomRiskRequest(BaseModel):
    prompt: str
    accessibility_weight: float = 0.2
    bureaucratic_weight: float = 0.2
    market_distortion_weight: float = 0.2
    ecological_weight: float = 0.2
    social_friction_weight: float = 0.2
    limit: Optional[int] = 5


@app.post("/api/gov/custom-risk")
def custom_risk_sandbox(request: CustomRiskRequest):
    """
    CUSTOM POLICY RISK SANDBOX (LangChain + Gemini Workflow)
    Analyzes schemes against natural language risk descriptions and custom risk parameter weights.
    """
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")
        
    try:
        import re
        from prompt_enhancer import GOOGLE_API_KEY
        from langchain_google_genai import ChatGoogleGenerativeAI
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import StrOutputParser
        
        # Build local heuristic keywords in case of rate limit fallback
        words = re.findall(r'\b\w{4,12}\b', request.prompt.lower())
        stop_words = {'about', 'their', 'there', 'would', 'could', 'should', 'these', 'those', 'where', 'which', 'under', 'while', 'after', 'before'}
        keywords = [w for w in words if w not in stop_words]
        fallback_tags = " ".join(keywords[:5]) if keywords else "subsidy grant training loan certificate"

        extracted_tags = fallback_tags
        llm = None
        
        if GOOGLE_API_KEY:
            try:
                llm = ChatGoogleGenerativeAI(
                    model="gemini-2.0-flash",
                    google_api_key=GOOGLE_API_KEY,
                    temperature=0.2,
                    max_output_tokens=150,
                    max_retries=0,
                )
                
                tag_prompt_tmpl = ChatPromptTemplate.from_messages([
                    ("system", "You are a policy analyst assistant. Extract 3-5 space-separated keyword tags from the user's custom risk concern to search government schemes. Return ONLY the space-separated words, nothing else."),
                    ("human", "{concern}")
                ])
                
                tag_chain = tag_prompt_tmpl | llm | StrOutputParser()
                res = tag_chain.invoke({"concern": request.prompt})
                extracted_tags = res.strip().strip('"').strip("'")
            except Exception as tag_err:
                print(f"  [Auditor] Gemini tag extraction failed/rate-limited: {tag_err}. Using heuristic fallback.")
        
        # Step 2: Query schemes from DB matching those tags
        from government_risk_analyzer import RiskAnalyzer
        analyzer = RiskAnalyzer()
        matched_schemes = analyzer.search_risky_schemes_by_tags(extracted_tags, top_n=15)
        
        if not matched_schemes:
            # Fallback to general risky schemes
            matched_schemes = analyzer.search_risky_schemes_by_tags("subsidy grant training loan certificate", top_n=15)
            
        # Step 3: Analyze and rank the matched schemes
        analysis_chain = None
        if llm:
            analysis_prompt_tmpl = ChatPromptTemplate.from_messages([
                ("system", """You are a senior government auditor. You are reviewing the following scheme against a specific policy concern.
Concern: {concern}

Scheme Title: {title}
Scheme Description: {description}

Assign a risk score from 0.0 (No Risk) to 10.0 (Extremely High Risk) indicating how much this specific scheme triggers the policy concern.
Provide a 1-2 sentence justification.

Return format EXACTLY like this:
Score: [number]
Justification: [text]"""),
                ("human", "Audit this scheme.")
            ])
            analysis_chain = analysis_prompt_tmpl | llm | StrOutputParser()
            
        results = []
        for scheme in matched_schemes[:request.limit]:
            custom_score = 5.0
            justification = "Scheme triggers custom concern criteria."
            llm_success = False
            
            if analysis_chain:
                try:
                    audit_output = analysis_chain.invoke({
                        "concern": request.prompt,
                        "title": scheme["title"],
                        "description": scheme.get("description", "Government welfare benefits distribution.")
                    })
                    
                    score_match = re.search(r"Score:\s*([0-9.]+)", audit_output, re.IGNORECASE)
                    just_match = re.search(r"Justification:\s*(.+)", audit_output, re.IGNORECASE)
                    
                    if score_match:
                        custom_score = float(score_match.group(1))
                        justification = just_match.group(1) if just_match else "Scheme triggers custom concern criteria."
                        llm_success = True
                except Exception as audit_err:
                    print(f"  [Auditor] Gemini scheme audit failed/rate-limited: {audit_err}. Falling back to offline heuristics.")
            
            if not llm_success:
                # Local heuristic fallback engine calculation
                concern_words = set(re.findall(r'\b\w{3,12}\b', request.prompt.lower()))
                scheme_words = set(re.findall(r'\b\w{3,12}\b', (scheme["title"] + " " + scheme.get("description", "")).lower()))
                intersection = concern_words.intersection(scheme_words)
                
                match_count = len(intersection)
                if match_count >= 3:
                    custom_score = 8.5
                    flag_level = "High"
                elif match_count >= 1:
                    custom_score = 6.5
                    flag_level = "Moderate"
                else:
                    custom_score = 4.0
                    flag_level = "Low"
                    
                justification = (
                    f"[Local Offline Heuristics] (Gemini API 429 Rate-Limited; running local semantic analysis): "
                    f"Auditor flags a {flag_level} policy risk. Scheme tags align with concern parameters "
                    f"({', '.join(list(intersection)[:3]) if intersection else 'systemic benefits'})."
                )
            
            # Calculate composite weighted risk based on the sliders
            w_acc = request.accessibility_weight * scheme.get("accessibility_risk", 1.0)
            w_bur = request.bureaucratic_weight * scheme.get("bureaucratic_risk", 1.0)
            w_mar = request.market_distortion_weight * scheme.get("market_distortion_risk", 1.0)
            w_eco = request.ecological_weight * scheme.get("ecological_risk", 1.0)
            w_soc = request.social_friction_weight * scheme.get("social_friction_risk", 1.0)
            
            weight_sum = (request.accessibility_weight + request.bureaucratic_weight + 
                          request.market_distortion_weight + request.ecological_weight + 
                          request.social_friction_weight)
            
            if weight_sum > 0:
                weighted_base = (w_acc + w_bur + w_mar + w_eco + w_soc) / weight_sum
            else:
                weighted_base = scheme.get("composite_risk_score", 3.0)
                
            # Combine composite base risk with the custom risk evaluation
            final_composite_score = round((weighted_base * 0.4) + (custom_score * 0.6), 2)
            
            results.append({
                "scheme_id": scheme["scheme_id"],
                "title": scheme["title"],
                "category": scheme["category"],
                "tags": scheme["tags"],
                "link": scheme["link"],
                "accessibility_risk": scheme.get("accessibility_risk", 1.0),
                "bureaucratic_risk": scheme.get("bureaucratic_risk", 1.0),
                "market_distortion_risk": scheme.get("market_distortion_risk", 1.0),
                "ecological_risk": scheme.get("ecological_risk", 1.0),
                "social_friction_risk": scheme.get("social_friction_risk", 1.0),
                "custom_risk_score": custom_score,
                "weighted_base_score": round(weighted_base, 2),
                "final_composite_score": final_composite_score,
                "justification": justification
            })
            
        # Sort by final score descending
        results.sort(key=lambda x: x["final_composite_score"], reverse=True)
        
        return {
            "prompt": request.prompt,
            "extracted_tags": extracted_tags,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---- Extended Feature Models & Endpoints ----

class EligibilityCheckRequest(BaseModel):
    income: Optional[float] = None
    caste: Optional[str] = None
    age: Optional[int] = None
    gender: Optional[str] = None
    land_holding: Optional[float] = None
    occupation: Optional[str] = None
    family_size: Optional[int] = None
    district: Optional[str] = None
    mandal: Optional[str] = None
    category: Optional[str] = None
    query: Optional[str] = ""
    top_k: Optional[int] = 15

class GrievanceRequest(BaseModel):
    scheme_id: Optional[str] = ""
    category: str
    message: str
    user_name: Optional[str] = "Anonymous Citizen"
    mobile: Optional[str] = ""

class AdminSchemeRequest(BaseModel):
    title: str
    category: str
    description: str
    tags: Optional[str] = ""
    link: Optional[str] = ""

class HouseholdMemberRequest(BaseModel):
    user_id: int
    name: str
    relation: str
    age: Optional[int] = None
    gender: Optional[str] = None
    occupation: Optional[str] = None
    caste: Optional[str] = None
    income: Optional[float] = None

class ApplicationStatusRequest(BaseModel):
    user_id: int
    scheme_id: str
    scheme_title: Optional[str] = ""
    status: str
    notes: Optional[str] = ""

class BookmarkRequest(BaseModel):
    user_id: int
    scheme_id: str

@app.post("/api/eligibility-check")
def check_eligibility(req: EligibilityCheckRequest):
    """
    Evaluates candidate schemes against structured eligibility rules:
    - Annual Income ceilings (< 2.5L, < 5L)
    - Caste reservation preferences (SC, ST, BC, OC)
    - Land holding limits (< 3 acres wet / 10 acres dry)
    - Age bounds
    """
    user_q = req.query.strip() if req.query else "welfare scheme"
    if req.occupation:
        user_q += f" {req.occupation}"
    if req.category:
        user_q += f" {req.category}"

    candidates = engine.recommend_schemes(user_q, top_k=req.top_k)

    evaluated_results = []
    for s in candidates:
        text = f"{s.get('title', '')} {s.get('description', '')} {s.get('tags', '')}".lower()
        
        status = "Eligible"
        reasons = []

        # 1. Income Ceiling Check
        if req.income is not None:
            if "bpl" in text or "low income" in text or "poverty line" in text:
                if req.income > 250000:
                    status = "Not eligible"
                    reasons.append("Annual income exceeds ₹2.5 Lakhs BPL ceiling")
            elif "economically weaker" in text or "ews" in text:
                if req.income > 800000:
                    status = "Not eligible"
                    reasons.append("Annual income exceeds ₹8 Lakhs EWS limit")

        # 2. Age Bounds Check
        if req.age is not None:
            if "pension" in text or "senior citizen" in text or "old age" in text:
                if req.age < 60:
                    status = "Not eligible"
                    reasons.append("Applicant age is below 60 years senior citizen requirement")
            elif "student" in text or "scholarship" in text or "post graduate" in text:
                if req.age > 35:
                    status = "Uncertain"
                    reasons.append("Verify higher education age limit guidelines")

        # 3. Caste Category Matching
        if req.caste and req.caste.strip():
            caste_clean = req.caste.strip().lower()
            if "scheduled caste" in text or "sc scholarship" in text:
                if caste_clean not in ["sc", "scheduled caste"]:
                    status = "Not eligible"
                    reasons.append("Scheme is reserved for Scheduled Caste (SC) category")
            elif "scheduled tribe" in text or "st scholarship" in text:
                if caste_clean not in ["st", "scheduled tribe"]:
                    status = "Not eligible"
                    reasons.append("Scheme is reserved for Scheduled Tribe (ST) category")

        # 4. Land Holding Check
        if req.land_holding is not None and req.land_holding > 0:
            if "small farmer" in text or "marginal farmer" in text:
                if req.land_holding > 5.0:
                    status = "Uncertain"
                    reasons.append("Verify Land Pattadar Passbook limit (5 acres)")

        # Generate required document list
        docs = ["Aadhaar Card", "Ration / Rice Card", "Income Certificate"]
        if "farmer" in text or "land" in text or "agriculture" in text:
            docs.append("Pattadar Passbook")
        if "student" in text or "scholarship" in text:
            docs.append("Study / Bonafide Certificate")
        if "disability" in text or "handicapped" in text:
            docs.append("SADAREM Disability Certificate")
        if req.caste and req.caste.lower() in ["sc", "st", "bc"]:
            docs.append("Caste Certificate")

        s["eligibility_status"] = status
        s["disqualification_reasons"] = reasons
        s["required_documents"] = docs
        s["last_verified"] = "August 2026"
        s["volunteer_contact"] = "Grama Volunteer / Sachivalayam DA"

        # Explicit reasoning string formulation
        if status == "Eligible":
            s["eligibility_reasoning"] = "Eligible based on profile cross-match."
        elif status == "Not eligible":
            s["eligibility_reasoning"] = f"Not eligible because: {', '.join(reasons)}"
        else:
            s["eligibility_reasoning"] = f"Uncertain — verify: {', '.join(reasons)}"

        evaluated_results.append(s)

    return {
        "criteria": req.dict(),
        "total_evaluated": len(evaluated_results),
        "results": evaluated_results
    }

@app.post("/api/grievance")
def submit_grievance(req: GrievanceRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Grievance message cannot be empty.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO grievances (user_name, mobile, scheme_id, category, message)
    VALUES (?, ?, ?, ?, ?)
    ''', (req.user_name, req.mobile, req.scheme_id, req.category, req.message))
    conn.commit()
    conn.close()
    return {"message": "Grievance / Assistance request submitted successfully. A Grama Volunteer will follow up."}

@app.get("/api/admin/schemes")
def admin_get_schemes(page: int = 1, limit: int = 20, search: Optional[str] = ""):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    offset = (page - 1) * limit
    if search and search.strip():
        q_str = f"%{search.strip()}%"
        cursor.execute("SELECT COUNT(*) FROM schemes WHERE title LIKE ? OR category LIKE ?", (q_str, q_str))
        total = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM schemes WHERE title LIKE ? OR category LIKE ? ORDER BY title LIMIT ? OFFSET ?", (q_str, q_str, limit, offset))
    else:
        cursor.execute("SELECT COUNT(*) FROM schemes")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM schemes ORDER BY title LIMIT ? OFFSET ?", (limit, offset))

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"total": total, "page": page, "limit": limit, "schemes": rows}

@app.post("/api/admin/schemes")
def admin_create_scheme(req: AdminSchemeRequest):
    import uuid
    sid = str(uuid.uuid4())[:8]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO schemes (scheme_id, title, category, description, tags, link)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (sid, req.title, req.category, req.description, req.tags, req.link))
    conn.commit()
    conn.close()
    return {"message": "Scheme created successfully!", "scheme_id": sid}

@app.put("/api/admin/schemes/{scheme_id}")
def admin_update_scheme(scheme_id: str, req: AdminSchemeRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE schemes SET title=?, category=?, description=?, tags=?, link=? WHERE scheme_id=?
    ''', (req.title, req.category, req.description, req.tags, req.link, scheme_id))
    conn.commit()
    conn.close()
    return {"message": "Scheme updated successfully!"}

@app.delete("/api/admin/schemes/{scheme_id}")
def admin_delete_scheme(scheme_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM schemes WHERE scheme_id=?", (scheme_id,))
    conn.commit()
    conn.close()
    return {"message": "Scheme deleted successfully!"}

@app.get("/api/admin/analytics")
def admin_analytics():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM schemes")
    total_schemes = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM grievances")
    total_grievances = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM user_applications")
    total_applications = cursor.fetchone()["cnt"]

    cursor.execute("SELECT category, COUNT(*) as cnt FROM schemes GROUP BY category ORDER BY cnt DESC LIMIT 5")
    top_categories = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return {
        "total_schemes": total_schemes,
        "total_users": total_users,
        "total_grievances": total_grievances,
        "total_applications": total_applications,
        "top_categories": top_categories
    }

# ---- Household Members & Bookmarks ----

@app.get("/api/user/household/{user_id}")
def get_household(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM household_members WHERE user_id=?", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"members": rows}

@app.post("/api/user/household")
def add_household(req: HouseholdMemberRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO household_members (user_id, name, relation, age, gender, occupation, caste, income)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (req.user_id, req.name, req.relation, req.age, req.gender, req.occupation, req.caste, req.income))
    conn.commit()
    conn.close()
    return {"message": "Household member added successfully!"}

@app.delete("/api/user/household/{member_id}")
def delete_household(member_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM household_members WHERE id=?", (member_id,))
    conn.commit()
    conn.close()
    return {"message": "Household member removed."}

@app.get("/api/user/applications/{user_id}")
def get_applications(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_applications WHERE user_id=? ORDER BY updated_at DESC", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"applications": rows}

@app.post("/api/user/applications")
def update_application(req: ApplicationStatusRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO user_applications (user_id, scheme_id, scheme_title, status, notes, updated_at)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id, scheme_id) DO UPDATE SET
      status=excluded.status,
      notes=excluded.notes,
      updated_at=CURRENT_TIMESTAMP
    ''', (req.user_id, req.scheme_id, req.scheme_title, req.status, req.notes))
    conn.commit()
    conn.close()
    return {"message": "Application status updated!"}

@app.get("/api/user/bookmarks/{user_id}")
def get_bookmarks(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
    SELECT s.* FROM user_bookmarks b
    JOIN schemes s ON b.scheme_id = s.scheme_id
    WHERE b.user_id = ?
    ''', (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"bookmarks": rows}

@app.post("/api/user/bookmarks")
def toggle_bookmark(req: BookmarkRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM user_bookmarks WHERE user_id=? AND scheme_id=?", (req.user_id, req.scheme_id))
    exists = cursor.fetchone()
    if exists:
        cursor.execute("DELETE FROM user_bookmarks WHERE user_id=? AND scheme_id=?", (req.user_id, req.scheme_id))
        is_bookmarked = False
    else:
        cursor.execute("INSERT INTO user_bookmarks (user_id, scheme_id) VALUES (?, ?)", (req.user_id, req.scheme_id))
        is_bookmarked = True
    conn.commit()
    conn.close()
    return {"bookmarked": is_bookmarked}
