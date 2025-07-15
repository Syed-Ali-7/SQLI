from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import os
import secrets
import re
from functools import wraps
from datetime import datetime, timedelta
import json
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address 
import smtplib
from patterns import SQLI_PATTERNS
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# NEW: Import ProxyFix
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

# Email Configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465
EMAIL_USER = 'saimatasneem006@gmail.com'
EMAIL_PASSWORD = 'rrbp wlty dhrr scte'  # Use app-specific password
ADMIN_EMAIL = 'saimatasneem006@gmail.com'




app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# NEW: Apply ProxyFix
# This tells Flask to trust X-Forwarded-For, X-Forwarded-Host, etc.
# The 'x_for=1' means it trusts one proxy (e.g., your test tool adding X-Forwarded-For).
# If you ever put a real Nginx/Apache in front, keep x_for=1. If you add *another* proxy,
# like a load balancer in front of Nginx, you'd increment this to x_for=2, etc.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_prefix=1)


# Rate limiting
# get_remote_address will now correctly use the IP from X-Forwarded-For
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)

def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        logging.info(f"Email notification sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")

class SecurityMiddleware:
    def __init__(self, app): # `app` is the Flask instance, not the WSGI app here
        self.app = app
        self.blocked_ips = set()
        self.failed_attempts = {}
        self.load_blocked_ips()
        self.sqli_patterns = SQLI_PATTERNS # Using the global patterns
    
    def load_blocked_ips(self):
        try:
            if os.path.exists("blocked_ips.json"):
                with open("blocked_ips.json", "r") as f:
                    data = json.load(f)
                    # Convert list of IPs from JSON back to a set
                    self.blocked_ips = set(data.get("ips", []))
        except Exception as e:
            logging.error(f"Error loading blocked IPs: {e}")
    
    def save_blocked_ips(self):
        try:
            with open("blocked_ips.json.tmp", "w") as f:
                json.dump({"ips": list(self.blocked_ips)}, f)
            os.rename("blocked_ips.json.tmp", "blocked_ips.json")
        except Exception as e:
            logging.error(f"Error saving blocked IPs: {e}")
    
    def detect_sqli(self, value):
        if not isinstance(value, str):
            value = str(value)
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(value)
            for pattern in self.sqli_patterns:
                # Search in both raw and decoded value
                if re.search(pattern, value, re.IGNORECASE) or re.search(pattern, decoded, re.IGNORECASE):
                    return True
        except Exception as e:
            logging.debug(f"Error during SQLI detection: {e} for value: {value}")
            pass
        return False
    
    def log_security_event(self, ip, event_type, details):
        event = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "event_type": event_type,
            "details": details
        }
        try:
            with open("security_events.json", "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logging.error(f"Error logging security event: {e}")
        logging.warning(f"Security Event - {event_type}: {ip} - {details}")
    
    def is_blocked(self, ip):
        return ip in self.blocked_ips
    
    def block_ip(self, ip, reason):
        if ip not in self.blocked_ips: # Only add if not already present
            self.blocked_ips.add(ip)
            self.save_blocked_ips()
            self.log_security_event(ip, "IP_BLOCKED", reason)
            subject = f"Security Alert: IP Blocked - {ip}"
            body = f"""
            Security Alert:
            An IP address has been blocked due to suspicious activity.
            Details:
            - IP Address: {ip}
            - Reason: {reason}
            - Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            send_email(subject, body)
    
    def check_rate_limit(self, ip):
        now = datetime.now()
        # Clean up old attempts
        if ip in self.failed_attempts:
            self.failed_attempts[ip] = [
                attempt for attempt in self.failed_attempts[ip]
                if now - attempt < timedelta(hours=1)
            ]
        else:
            self.failed_attempts[ip] = [] # Initialize if not present
            
        if len(self.failed_attempts[ip]) >= 10:
            return False
        return True
    
    def record_failed_attempt(self, ip):
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        self.failed_attempts[ip].append(datetime.now())

# Instantiate your SecurityMiddleware
security_middleware = SecurityMiddleware(app)

def init_db():
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='students'")
    table_exists = cursor.fetchone()
    
    if not table_exists:
        cursor.execute('''
        CREATE TABLE students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            major TEXT NOT NULL,
            gpa REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES students (id)
        )
        ''')
        
        students = [
            ('john_doe', generate_password_hash('SecurePass123!'), 'John Doe', 'john@university.edu', 'Computer Science', 3.8),
            ('jane_smith', generate_password_hash('StrongPass456!'), 'Jane Smith', 'jane@university.edu', 'Biology', 3.9),
            ('bob_johnson', generate_password_hash('ComplexPass789!'), 'Bob Johnson', 'bob@university.edu', 'Mathematics', 3.5),
            ('admin', generate_password_hash('Admin@pass2025'), 'Admin User', 'admin@university.edu', 'Administration', 4.0)
        ]
        
        cursor.executemany('''
        INSERT INTO students (username, password_hash, name, email, major, gpa)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', students)
        conn.commit()
        print("Database initialized with sample data")
    else:
        cursor.execute("PRAGMA table_info(students)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Check for password migration and is_active column
        if 'password' in columns and 'password_hash' not in columns:
            print("Migrating database: Adding password_hash...")
            cursor.execute("ALTER TABLE students ADD COLUMN password_hash TEXT")
            cursor.execute("SELECT id, password FROM students")
            users = cursor.fetchall()
            for user_id, plain_password in users:
                hashed_password = generate_password_hash(plain_password)
                cursor.execute("UPDATE students SET password_hash = ? WHERE id = ?", 
                             (hashed_password, user_id))
            print("Password hashing migration completed.")
            
        if 'is_active' not in columns:
            print("Migrating database: Adding is_active column...")
            cursor.execute("ALTER TABLE students ADD COLUMN is_active BOOLEAN DEFAULT 1")
            print("is_active column added.")

        conn.commit()
    conn.close()

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session and 'admin_logged_in' not in session:
            # Added a redirect to login page for better UX for unauthorized access
            # Or you can keep jsonify if it's an API endpoint
            return redirect(url_for('admin_login')) # Or a general login page
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check simple admin login (for the hardcoded 'admin'/'admin' login)
        if session.get('admin_logged_in'):
            return f(*args, **kwargs)
        
        # Check database admin login
        if 'user_id' in session:
            conn = sqlite3.connect('students.db')
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM students WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            if user and user[0] == 'admin':
                return f(*args, **kwargs)
        
        return jsonify({'error': 'Admin access required'}), 403
    return decorated_function

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        if session.get('admin_logged_in') or (session.get('user_id') and session.get('username') == 'admin'):
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html')
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Simple hardcoded admin login for dashboard access
    if username == 'admin' and password == 'admin': # This is a direct admin login for dashboard
        session['admin_logged_in'] = True
        security_middleware.log_security_event(request.remote_addr, "ADMIN_LOGIN_SUCCESS", "Hardcoded admin login")
        return redirect(url_for('admin_dashboard'))
    
    # Check against database admin user
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash, username FROM students WHERE username = 'admin'")
    admin_user = cursor.fetchone()
    conn.close()

    if admin_user and check_password_hash(admin_user[1], password):
        session['user_id'] = admin_user[0]
        session['username'] = admin_user[2]
        session['admin_logged_in'] = True # Set this for consistency with require_admin
        security_middleware.log_security_event(request.remote_addr, "ADMIN_LOGIN_SUCCESS", "Database admin login")
        return redirect(url_for('admin_dashboard'))

    security_middleware.log_security_event(request.remote_addr, "ADMIN_LOGIN_FAILED", f"Invalid credentials for admin user: {username}")
    return render_template('admin_login.html', error='Invalid credentials'), 401

@app.route('/admin/logout')
def admin_logout():
    username = session.get('username', 'unknown_admin')
    session.pop('admin_logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    security_middleware.log_security_event(request.remote_addr, "ADMIN_LOGOUT", f"Admin: {username}")
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.before_request
def security_check():
    # request.remote_addr now gets the correct IP due to ProxyFix
    ip = request.remote_addr 
    
    if security_middleware.is_blocked(ip):
        return render_template('access_denied.html'), 403
    
    suspicious_data = []
    # Check JSON body
    if request.is_json:
        try:
            json_data = request.get_json()
            if isinstance(json_data, dict): # Ensure it's a dictionary before iterating
                for key, value in json_data.items():
                    if security_middleware.detect_sqli(str(value)):
                        suspicious_data.append(f"json:{key}={value}")
            elif isinstance(json_data, list): # Handle JSON lists if applicable
                 for item in json_data:
                    if security_middleware.detect_sqli(str(item)):
                        suspicious_data.append(f"json_list_item:{item}")
            else: # Handle other JSON types (e.g., plain string, number)
                if security_middleware.detect_sqli(str(json_data)):
                    suspicious_data.append(f"json_body:{json_data}")

        except Exception as e:
            logging.debug(f"Could not parse JSON or detect SQLi in JSON: {e}")
            pass # Malformed JSON or other parsing error

    # Check query parameters
    for key, value in request.args.items():
        if security_middleware.detect_sqli(str(value)):
            suspicious_data.append(f"query:{key}={value}")
    
    # Check form data
    for key, value in request.form.items():
        if security_middleware.detect_sqli(str(value)):
            suspicious_data.append(f"form:{key}={value}")
    
    if suspicious_data:
        reason = f"SQL injection attempt: {'; '.join(suspicious_data)}"
        security_middleware.block_ip(ip, reason)
        return redirect(url_for('access_denied')) # Redirect to a generic access denied page

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/access-denied')
def access_denied():
    return render_template('access_denied.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # request.remote_addr now gets the correct IP due to ProxyFix
    ip = request.remote_addr 
    
    if not security_middleware.check_rate_limit(ip):
        return jsonify({'error': 'Too many attempts. IP blocked.'}), 429
    
    data = request.get_json()
    if not data:
        # If no JSON data, could be a regular form submission, but your code expects JSON.
        # Ensure your frontend sends JSON for login.
        return jsonify({'error': 'Invalid request format or missing JSON data'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        security_middleware.record_failed_attempt(ip)
        return jsonify({'error': 'Username and password required'}), 400
    
    # Basic input length validation
    if len(username) > 50 or len(password) > 128:
        security_middleware.record_failed_attempt(ip)
        return jsonify({'error': 'Invalid input length'}), 400
    
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT id, username, password_hash, name, email, major, gpa FROM students WHERE username = ?", 
            (username,)
        )
        student = cursor.fetchone()
        
        if not student:
            security_middleware.record_failed_attempt(ip)
            security_middleware.log_security_event(ip, "LOGIN_FAILED", f"Username not found: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        try:
            cursor.execute("SELECT is_active FROM students WHERE id = ?", (student[0],))
            active_result = cursor.fetchone()
            if active_result and not active_result[0]:
                security_middleware.record_failed_attempt(ip) # Record for disabled accounts too
                security_middleware.log_security_event(ip, "LOGIN_FAILED", f"Account disabled: {username}")
                return jsonify({'error': 'Account is disabled'}), 401
        except sqlite3.OperationalError:
            # If 'is_active' column doesn't exist, assume active
            logging.warning("is_active column not found, assuming account is active.")
            pass 
        
        password_hash = student[2]
        if check_password_hash(password_hash, password):
            session['user_id'] = student[0]
            session['username'] = student[1]
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=2)
            
            try:
                cursor.execute(
                    "UPDATE students SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (student[0],))
                conn.commit()
            except sqlite3.OperationalError:
                logging.warning("Could not update last_login, column might be missing.")
                pass
            
            # Clear failed attempts for this IP on successful login
            if ip in security_middleware.failed_attempts:
                del security_middleware.failed_attempts[ip]

            security_middleware.log_security_event(ip, "LOGIN_SUCCESS", f"User: {username}")
            
            student_data = {
                'id': student[0],
                'username': student[1],
                'name': student[3],
                'email': student[4],
                'major': student[5],
                'gpa': student[6]
            }
            return jsonify({'student': student_data})
        else:
            security_middleware.record_failed_attempt(ip)
            security_middleware.log_security_event(ip, "LOGIN_FAILED", f"Wrong password for: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except sqlite3.Error as e:
        logging.error(f"Database error in login: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/logout', methods=['POST'])
@require_login
def logout():
    username = session.get('username', 'unknown')
    ip = request.remote_addr # Get the IP before clearing session
    session.clear()
    security_middleware.log_security_event(ip, "LOGOUT", f"User: {username}")
    return jsonify({'message': 'Logged out successfully'})

@app.route('/profile')
@require_login
def profile():
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT username, name, email, major, gpa FROM students WHERE id = ?",
            (session['user_id'],)
        )
        student = cursor.fetchone()
        if student:
            student_data = {
                'username': student[0],
                'name': student[1],
                'email': student[2],
                'major': student[3],
                'gpa': student[4]
            }
            return render_template('profile.html', student=student_data)
        else:
            session.clear() # Clear session if user not found, forcing re-login
            return jsonify({'error': 'User not found, session cleared'}), 404
    except sqlite3.Error as e:
        logging.error(f"Database error in profile: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/admin/security-events')
@require_admin
def view_security_events():
    try:
        events = []
        if os.path.exists('security_events.json'):
            with open('security_events.json', 'r') as f:
                for line in f:
                    try:
                        events.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        logging.warning(f"Skipping malformed JSON line in security_events.json: {line.strip()}")
                        continue
        # Sort by timestamp in descending order (most recent first)
        events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return jsonify({'events': events[:100]}) # Return last 100 events
    except Exception as e:
        logging.error(f"Error reading security events: {e}")
        return jsonify({'error': 'Unable to read security events'}), 500

@app.route('/admin/blocked-ips')
@require_admin
def view_blocked_ips():
    return jsonify({'blocked_ips': list(security_middleware.blocked_ips)})

@app.route('/admin/unblock-ip', methods=['POST'])
@require_admin
def unblock_ip():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    if ip in security_middleware.blocked_ips:
        security_middleware.blocked_ips.remove(ip)
        security_middleware.save_blocked_ips()
        # Log the admin's IP who performed the unblock action
        security_middleware.log_security_event(
            request.remote_addr, 
            "IP_UNBLOCKED", 
            f"Admin unblocked IP: {ip}"
        )
        # Clear any failed attempts for the unblocked IP
        if ip in security_middleware.failed_attempts:
            del security_middleware.failed_attempts[ip]

        return jsonify({'message': f'IP {ip} unblocked successfully'})
    else:
        return jsonify({'error': 'IP not found in blocked list'}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(403)
def forbidden_handler(e):
    return jsonify({'error': 'Access forbidden'}), 403

@app.errorhandler(500)
def internal_error_handler(e):
    logging.error(f"Internal server error: {e}", exc_info=True) # Log traceback
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/debug/reset-db')
def reset_database():
    if app.debug: # Only allow in debug mode
        try:
            if os.path.exists('students.db'):
                os.remove('students.db')
            if os.path.exists('blocked_ips.json'):
                os.remove('blocked_ips.json')
            if os.path.exists('security_events.json'):
                os.remove('security_events.json')
            
            init_db()
            # Reset in-memory blocked IPs and failed attempts as well
            security_middleware.blocked_ips.clear()
            security_middleware.failed_attempts.clear()

            return jsonify({
                'message': 'Database and security logs reset successfully',
                'test_credentials': {
                    'admin_dashboard_hardcoded': 'admin / admin', # Clarify this is for the dashboard
                    'admin_db_user': 'admin / Admin@pass2025',
                    'john_doe': 'SecurePass123!',
                    'jane_smith': 'StrongPass456!',
                    'bob_johnson': 'ComplexPass789!'
                }
            })
        except Exception as e:
            return jsonify({'error': f'Failed to reset database: {str(e)}'}), 500
    else:
        return jsonify({'error': 'Not available in production mode'}), 404

if __name__ == '__main__':
    # Initialize the database and security data
    init_db()
    security_middleware.load_blocked_ips() # Ensure IPs are loaded on startup
    app.run(host='0.0.0.0', port=10000, debug=True)