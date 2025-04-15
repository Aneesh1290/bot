import qrcode
import time
import random
import string
import gspread
import json
import csv
from flask import Flask, send_file, request, jsonify, render_template, session, redirect, url_for, make_response
from oauth2client.service_account import ServiceAccountCredentials
from twilio.twiml.messaging_response import MessagingResponse
from io import BytesIO, StringIO
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'  # Change for production!

# Configuration
QR_EXPIRATION = 30  # seconds
OTP_EXPIRATION = 120  # seconds
OTP_LENGTH = 4
SECRET_KEY_LENGTH = 6

# Admin credentials (CHANGE THESE IN PRODUCTION!)
ADMIN_CREDENTIALS = {
    "username": "ASET",
    "password": "amity@2023"
}

# Google Sheets Setup
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)
client = gspread.authorize(creds)
sheet = client.open("Attendance").sheet1

# Data stores
active_qr_codes = {}
issued_otps = {}
pending_user_info = {}

current_class = {
    "teacher_name": "",
    "teacher_id": "",
    "subject_code": "",
    "subject_name": "",
    "class_section": ""
}

# Helper Functions
def generate_secret_key():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=SECRET_KEY_LENGTH)).lower()

def generate_otp():
    return ''.join(random.choices(string.digits, k=OTP_LENGTH))

# Auth Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Main Routes
@app.route('/')
def index():
    """Redirect root to admin login"""
    return redirect(url_for('admin_login'))

@app.route('/display_qr')
@login_required
def display_qr():
    return render_template('qr_display.html', 
                         teacher_name=current_class["teacher_name"],
                         subject_code=current_class["subject_code"],
                         subject_name=current_class["subject_name"],
                         class_section=current_class["class_section"],
                         current_date=time.strftime("%Y-%m-%d"))

@app.route('/generate_qr', methods=['GET'])
def generate_qr():
    secret_key = generate_secret_key().lower()
    active_qr_codes[secret_key] = time.time() + QR_EXPIRATION
    
    whatsapp_url = f"https://api.whatsapp.com/send?phone=14155238886&text=Request+OTP+{secret_key}"
    
    qr = qrcode.make(whatsapp_url)
    qr_io = BytesIO()
    qr.save(qr_io, 'PNG')
    qr_io.seek(0)

    response = send_file(qr_io, mimetype='image/png')
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

@app.route('/whatsapp', methods=['POST'])
def whatsapp_webhook():
    from_number = request.form.get("From", "").replace("whatsapp:", "").strip()
    message_body = request.form.get("Body", "").strip()
    response = MessagingResponse()

    # Step 1: Handle QR Code Validation
    if message_body.lower().startswith("request otp"):
        secret_code = message_body.split(" ")[-1].lower()

        if secret_code not in active_qr_codes:
            response.message("❌ Invalid QR code! Please scan a fresh one.")
            return str(response)

        if time.time() > active_qr_codes[secret_code]:
            response.message("⏳ QR code expired! Please scan a new one.")
            return str(response)

        # Store user's QR verification for next step
        pending_user_info[from_number] = {
            "qr_secret": secret_code,
            "timestamp": time.time()
        }

        response.message(
            "✅ QR verified!\n"
            "📩 Please send your *Enrollment Number* and *Full Name* (space separated):\n"
            "Example: `A12345678 John Doe`"
        )
        return str(response)

    # Step 2: Handle Enrollment + Name Submission (after QR verification)
    elif from_number in pending_user_info:
        try:
            parts = message_body.split()
            if len(parts) < 2:
                raise ValueError("Incomplete input")

            enrollment = parts[0]
            name = " ".join(parts[1:])
            qr_info = pending_user_info[from_number]

            if time.time() - qr_info["timestamp"] > 180:
                del pending_user_info[from_number]
                response.message("⏳ Session expired! Please scan QR code again.")
                return str(response)

            # Record attendance
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            sheet.append_row([
                from_number,
                enrollment,
                name,
                timestamp,
                current_class["subject_code"],
                current_class["subject_name"],
                current_class["teacher_name"],
                "Present"
            ])

            # Clean up
            del pending_user_info[from_number]
            del active_qr_codes[qr_info["qr_secret"]]

            response.message(
                f"✅ Attendance marked successfully!\n"
                f"🧑 Name: {name}\n"
                f"🆔 Enrollment: {enrollment}\n"
                f"📘 Subject: {current_class['subject_name']}\n"
                f"👨‍🏫 Teacher: {current_class['teacher_name']}\n"
                f"🕒 Time: {timestamp}"
            )

        except Exception:
            response.message("⚠️ Please send your *Enrollment Number* and *Full Name* properly (e.g., `A12345678 John Doe`).")
        return str(response)

    # Default fallback
    response.message("🤖 Please start by scanning a QR code using:\n'Request OTP <code>'")
    return str(response)

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_CREDENTIALS['username'] and password == ADMIN_CREDENTIALS['password']:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error="Invalid credentials")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    try:
        records = sheet.get_all_records()
    except Exception as e:
        records = []
    
    return render_template('admin_dashboard.html', 
                         records=records,
                         current_class=current_class)

@app.route('/admin/update_class', methods=['POST'])
@login_required
def update_class():
    current_class["teacher_name"] = request.form.get("teacher_name")
    current_class["teacher_id"] = request.form.get("teacher_id")
    current_class["subject_code"] = request.form.get("subject_code")
    current_class["subject_name"] = request.form.get("subject_name")
    current_class["class_section"] = request.form.get("class_section")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear_attendance', methods=['POST'])
@login_required
def clear_attendance():
    try:
        sheet.clear()
        sheet.append_row(["Phone Number",
            "Enrollment Number",
            "Student Name", 
            "Timestamp",
            "Subject Code",
            "Subject Name",
            "Teacher",
            "Status"])
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/export_csv')
@login_required
def export_csv():
    try:
        records = sheet.get_all_records()
        
        csv_data = StringIO()
        csv_writer = csv.DictWriter(csv_data, fieldnames=[
            "Phone Number",
            "Enrollment Number",
            "Student Name", 
            "Timestamp",
            "Subject Code",
            "Subject Name",
            "Teacher",
            "Status"
        ])
        
        csv_writer.writeheader()
        csv_writer.writerows(records)
        
        response = make_response(csv_data.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=attendance_records.csv'
        response.headers['Content-type'] = 'text/csv'
        return response
        
    except Exception as e:
        return redirect(url_for('admin_dashboard'))
    
@app.route('/admin/attendance')
@login_required
def view_attendance():
    try:
        records = sheet.get_all_records()
    except Exception as e:
        records = []
    
    # Check if it's an AJAX request (for refresh)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('attendance_table.html', records=records)
    
    return render_template('attendance_records.html', records=records)

if __name__ == '__main__':
    app.run(debug=True)