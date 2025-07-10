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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

# SQL Injection Patterns
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"exec(\s|\+)+(s|x)p\w+",
    r"insert(\s|\+)+into",
    r"select(\s|\+)+from",
    r"delete(\s|\+)+from",
    r"update(\s|\+)+set",
    r"drop(\s|\+)+table",
    r"truncate(\s|\+)+table",
    r"create(\s|\+)+table",
    r"alter(\s|\+)+table",
    r"1=1",
    r"1\s*=\s*1",
    r"\' OR \'1\'=\'1",
    r"\" OR \"1\"=\"1",
    r"OR 1=1",
    r"AND 1=1",
    r"sleep\(\s*\d+\s*\)",
    r"benchmark\(\s*\d+",
    r"waitfor delay",
    r"shutdown(\s|\+)+with(\s|\+)+nowait",
    r"xp_cmdshell",
    r"\/\*.*\*\/"
]

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a secure secret key
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)

def send_email(subject, body):
    """Send email notification to admin"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(body, 'plain'))
        
        # Create SMTP session
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        logging.info(f"Email notification sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")

# Enhanced Security Middleware
class SecurityMiddleware:
    def __init__(self, app):
        self.app = app
        self.blocked_ips = set()
        self.failed_attempts = {}
        self.load_blocked_ips()
        self.sqli_patterns = SQLI_PATTERNS
    
    def load_blocked_ips(self):
        try:
            if os.path.exists("blocked_ips.json"):
                with open("blocked_ips.json", "r") as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get("ips", []))
        except Exception as e:
            logging.error(f"Error loading blocked IPs: {e}")
    
    def save_blocked_ips(self):
        try:
            with open("blocked_ips.json", "w") as f:
                json.dump({"ips": list(self.blocked_ips)}, f)
        except Exception as e:
            logging.error(f"Error saving blocked IPs: {e}")
    
    def detect_sqli(self, value):
        if not isinstance(value, str):
            value = str(value)
        
        # Decode common encodings
        import urllib.parse
        try:
            decoded = urllib.parse.unquote(value)
            # Check both original and decoded
            for pattern in self.sqli_patterns:
                if re.search(pattern, value) or re.search(pattern, decoded):
                    return True
        except:
            pass
        
        return False
    
    def log_security_event(self, ip, event_type, details):
        event = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "event_type": event_type,
            "details": details
        }
        
        # Log to file
        try:
            with open("security_events.json", "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logging.error(f"Error logging security event: {e}")
        
        # Log to application logger
        logging.warning(f"Security Event - {event_type}: {ip} - {details}")
    
    def is_blocked(self, ip):
        return ip in self.blocked_ips
    
    def block_ip(self, ip, reason):
        self.blocked_ips.add(ip)
        self.save_blocked_ips()
        self.log_security_event(ip, "IP_BLOCKED", reason)
        
        # Send email notification
        subject = f"Security Alert: IP Blocked - {ip}"
        body = f"""
        Security Alert:
        
        An IP address has been blocked due to suspicious activity.
        
        Details:
        - IP Address: {ip}
        - Reason: {reason}
        - Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        This is an automated notification from your security system.
        """
        send_email(subject, body)
    
    def check_rate_limit(self, ip):
        now = datetime.now()
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        
        # Clean old attempts (older than 1 hour)
        self.failed_attempts[ip] = [
            attempt for attempt in self.failed_attempts[ip]
            if now - attempt < timedelta(hours=1)
        ]
        
        # Check if too many recent attempts
        if len(self.failed_attempts[ip]) >= 10:  # 10 attempts per hour
            return False
        
        return True
    
    def record_failed_attempt(self, ip):
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        self.failed_attempts[ip].append(datetime.now())

# Initialize middleware
security_middleware = SecurityMiddleware(app)

# Database initialization with secure password hashing
def init_db():
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    # Check if students table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='students'")
    table_exists = cursor.fetchone()
    
    if not table_exists:
        # Create students table with hashed passwords
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
        
        # Create sessions table
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
        
        # Insert sample data with hashed passwords
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
        print("Test credentials:")
        print("- admin / Admin@pass2025")
        print("- john_doe / SecurePass123!")
    else:
        # Check if we need to migrate from old schema (plain text passwords)
        cursor.execute("PRAGMA table_info(students)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'password' in columns and 'password_hash' not in columns:
            print("Migrating database from plain text passwords to hashed passwords...")
            
            # Add new column
            cursor.execute("ALTER TABLE students ADD COLUMN password_hash TEXT")
            
            # Get all users with plain text passwords
            cursor.execute("SELECT id, password FROM students")
            users = cursor.fetchall()
            
            # Hash existing passwords
            for user_id, plain_password in users:
                hashed_password = generate_password_hash(plain_password)
                cursor.execute("UPDATE students SET password_hash = ? WHERE id = ?", 
                             (hashed_password, user_id))
            
            # Add is_active column if it doesn't exist
            if 'is_active' not in columns:
                cursor.execute("ALTER TABLE students ADD COLUMN is_active BOOLEAN DEFAULT 1")
            
            conn.commit()
            print("Migration completed. Old passwords have been hashed.")
    
    conn.close()

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check if user is admin
        conn = sqlite3.connect('students.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM students WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[0] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def security_check():
    ip = request.remote_addr
    
    # Check if IP is blocked
    if security_middleware.is_blocked(ip):
        return render_template('access_denied.html'), 403
    
    # Check for SQL injection in request
    suspicious_data = []
    
    # Check JSON data
    if request.is_json:
        try:
            json_data = request.get_json()
            if json_data:
                for key, value in json_data.items():
                    if security_middleware.detect_sqli(str(value)):
                        suspicious_data.append(f"{key}={value}")
        except:
            pass
    
    # Check query parameters
    for key, value in request.args.items():
        if security_middleware.detect_sqli(str(value)):
            suspicious_data.append(f"query:{key}={value}")
    
    # Check form data
    for key, value in request.form.items():
        if security_middleware.detect_sqli(str(value)):
            suspicious_data.append(f"form:{key}={value}")
    
    # If suspicious activity detected
    if suspicious_data:
        reason = f"SQL injection attempt: {'; '.join(suspicious_data)}"
        security_middleware.block_ip(ip, reason)
        return redirect(url_for('access_denied'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/access-denied')
def access_denied():
    return render_template('access_denied.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    ip = request.remote_addr
    
    # Check rate limiting
    if not security_middleware.check_rate_limit(ip):
        security_middleware.block_ip(ip, "Too many login attempts")
        return jsonify({'error': 'Too many attempts. IP blocked.'}), 429
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request format'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Input validation
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if len(username) > 50 or len(password) > 128:
        return jsonify({'error': 'Invalid input length'}), 400
    
    # Use parameterized query to prevent SQL injection
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    try:
        # First check if user exists
        cursor.execute(
            "SELECT id, username, password_hash, name, email, major, gpa FROM students WHERE username = ?", 
            (username,)
        )
        student = cursor.fetchone()
        
        if not student:
            # User doesn't exist
            security_middleware.record_failed_attempt(ip)
            security_middleware.log_security_event(ip, "LOGIN_FAILED", f"Username not found: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if user is active
        try:
            cursor.execute("SELECT is_active FROM students WHERE id = ?", (student[0],))
            active_result = cursor.fetchone()
            if active_result and not active_result[0]:
                return jsonify({'error': 'Account is disabled'}), 401
        except sqlite3.OperationalError:
            pass
        
        # Verify password
        password_hash = student[2]
        if check_password_hash(password_hash, password):
            # Successful login
            session['user_id'] = student[0]
            session['username'] = student[1]
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=2)
            
            # Update last login
            try:
                cursor.execute(
                    "UPDATE students SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (student[0],))
                conn.commit()
            except sqlite3.OperationalError:
                pass
            
            # Log successful login
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
            # Failed login - wrong password
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
    session.clear()
    security_middleware.log_security_event(request.remote_addr, "LOGOUT", f"User: {username}")
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
            return jsonify({'error': 'User not found'}), 404
            
    except sqlite3.Error as e:
        logging.error(f"Database error in profile: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    return render_template('admin_dashboard.html')

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
                        continue
        
        return jsonify({'events': events[-100:]})
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
        security_middleware.log_security_event(
            request.remote_addr, 
            "IP_UNBLOCKED", 
            f"Admin unblocked IP: {ip}"
        )
        return jsonify({'message': f'IP {ip} unblocked successfully'})
    else:
        return jsonify({'error': 'IP not found in blocked list'}), 404

# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(403)
def forbidden_handler(e):
    return jsonify({'error': 'Access forbidden'}), 403

@app.errorhandler(500)
def internal_error_handler(e):
    logging.error(f"Internal error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/debug/reset-db')
def reset_database():
    """Development endpoint to reset database - remove in production"""
    if app.debug:
        try:
            if os.path.exists('students.db'):
                os.remove('students.db')
            init_db()
            return jsonify({
                'message': 'Database reset successfully',
                'test_credentials': {
                    'admin': 'AdminPass2024!',
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
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)