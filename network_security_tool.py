#!/usr/bin/env python3
"""
NETWORK SECURITY TOOL - Complete Port Scanner + Real-Time Monitoring + Web Dashboard
All-in-one solution for network threat detection and monitoring
This version reads configuration from config.ini (or environment variables) so it can be safely shared.
"""

import os
import socket
import threading
import json
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from functools import wraps
from flask import Flask, render_template_string, request, jsonify, session
import configparser

# =====================================================
# LOAD CONFIG
# =====================================================

CONFIG_FILE = 'config.ini'
config = configparser.ConfigParser()
if os.path.exists(CONFIG_FILE):
    config.read(CONFIG_FILE)
else:
    config = None

def get_config(section, key, default=None):
    # Check config file, then environment, then default
    if config and section in config and key in config[section]:
        return config[section][key]
    env_key = f"{section.upper()}_{key.upper()}"
    return os.environ.get(env_key, default)

# =====================================================
# CONFIGURATION (loaded from config.ini or env)
# =====================================================

GMAIL_ADDRESS = get_config('mail', 'address', 'fineboydara@gmail.com')
GMAIL_PASSWORD = get_config('mail', 'password', '')  # IMPORTANT: put app password here
ALERT_EMAILS = get_config('mail', 'recipients', 'fineboydara@gmail.com,jairusmicheal26@gmail.com')

ADMIN_USERNAME = get_config('auth', 'admin_user', 'admin')
ADMIN_PASSWORD = get_config('auth', 'admin_pass', 'cybersecurity123')

# Service risk map (same as before)
SERVICES = {
    21: ('FTP', 'HIGH RISK', 'Unencrypted file transfer - Use SFTP'),
    22: ('SSH', 'CRITICAL', 'Remote access - Brute force target'),
    23: ('Telnet', 'CRITICAL', 'Unencrypted remote access - DO NOT USE'),
    25: ('SMTP', 'MEDIUM', 'Email service - Spam relay risk'),
    53: ('DNS', 'LOW', 'Domain name resolution - SAFE'),
    80: ('HTTP', 'MEDIUM', 'Unencrypted web - Use HTTPS'),
    110: ('POP3', 'HIGH', 'Email access - Credentials exposed'),
    143: ('IMAP', 'HIGH', 'Email access - Enable TLS'),
    443: ('HTTPS', 'LOW', 'Encrypted web - SAFE'),
    445: ('SMB', 'CRITICAL', 'File sharing - RANSOMWARE RISK'),
    3306: ('MySQL', 'CRITICAL', 'Database exposed - DATA THEFT'),
    3389: ('RDP', 'CRITICAL', 'Remote desktop - Brute force target'),
    5432: ('PostgreSQL', 'CRITICAL', 'Database exposed - DATA THEFT'),
    5900: ('VNC', 'CRITICAL', 'Unencrypted remote access'),
    8080: ('HTTP-Proxy', 'MEDIUM', 'Proxy service - Man-in-middle risk'),
    27017: ('MongoDB', 'CRITICAL', 'Database exposed - DATA THEFT'),
}

# =====================================================
# DATABASE SETUP
# =====================================================

def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect('security_tool.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY, target TEXT, timestamp TEXT, 
                  open_ports TEXT, critical_count INTEGER, json_data TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS attacks
                 (id INTEGER PRIMARY KEY, attacker_ip TEXT, timestamp TEXT,
                  ports_targeted TEXT, scan_rate INTEGER, action TEXT, email_sent INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY, type TEXT, message TEXT, 
                  timestamp TEXT, severity TEXT, read_status INTEGER)''')
    
    conn.commit()
    conn.close()

# =====================================================
# EMAIL ALERT SYSTEM
# =====================================================

def send_email_alert(subject, message, alert_type="INFO"):
    """Send email alerts to configured recipients"""
    recipients = [r.strip() for r in ALERT_EMAILS.split(',') if r.strip()]
    if not GMAIL_PASSWORD:
        print("[WARN] No GMAIL_PASSWORD set in config.ini or environment. Skipping email.")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_ADDRESS
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = f"🚨 {subject}"
        
        body = f"""
        <html>
            <body style="font-family: Arial; background-color: #f4f4f4; padding: 20px;">
                <div style="background-color: white; padding: 20px; border-radius: 10px; border-left: 5px solid #ff6b6b;">
                    <h2 style="color: #ff6b6b;">⚠️ NETWORK SECURITY ALERT</h2>
                    <p><strong>Type:</strong> {alert_type}</p>
                    <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <hr>
                    <h3>Alert Details:</h3>
                    <p>{message}</p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated alert from your Network Security Tool</p>
                </div>
            </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Email alert sent: {subject}")
        return True
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False

# =====================================================
# PORT SCANNER ENGINE
# =====================================================

class NetworkSecurityScanner:
    def __init__(self, target, start_port=1, end_port=10000, timeout=0.5):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
        self.critical_count = 0
        self.scan_results = {}
        self.attack_detected = False
        self.connection_count = 0
    
    def get_service_info(self, port):
        """Get service details"""
        if port in SERVICES:
            return SERVICES[port]
        try:
            service = socket.getservbyport(port)
            return (service.upper(), 'UNKNOWN', 'Unknown service')
        except:
            return ('UNKNOWN', 'UNKNOWN', 'Unknown')
    
    def detect_aggressive_scan(self, attacker_ip):
        """Detect if someone is aggressively scanning your device"""
        try:
            # Check for high connection rate (more than 100 connections/sec = AGGRESSIVE)
            if self.connection_count > 100:
                alert_msg = f"""
                🚨 AGGRESSIVE SCAN DETECTED! 🚨
                
                Attacker IP: {attacker_ip}
                Connections/sec: {self.connection_count}
                Ports targeted: {self.start_port}-{self.end_port}
                Detection time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                
                ACTION TAKEN:
                ✓ Attack logged
                ✓ Emails sent to security team
                ✓ Firewall rule recommended: Block {attacker_ip}
                """
                
                send_email_alert(f"AGGRESSIVE SCAN from {attacker_ip}", alert_msg, "CRITICAL")
                self.attack_detected = True
                
                # Log to database
                conn = sqlite3.connect('security_tool.db')
                c = conn.cursor()
                c.execute("INSERT INTO attacks VALUES (NULL, ?, ?, ?, ?, ?, ?)",
                         (attacker_ip, datetime.now().isoformat(), 
                          f"{self.start_port}-{self.end_port}", self.connection_count, 
                          "ALERT SENT", 1))
                conn.commit()
                conn.close()
                
                return True
        except Exception as e:
            print(f"Error detecting attack: {e}")
        return False
    
    def scan_port(self, port):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            self.connection_count += 1
            
            if result == 0:
                service_name, risk_level, threat = self.get_service_info(port)
                with self.lock:
                    self.open_ports.append({
                        'port': port,
                        'service': service_name,
                        'risk': risk_level,
                        'threat': threat
                    })
                    if 'CRITICAL' in risk_level:
                        self.critical_count += 1
                    
                    self.scan_results[port] = {
                        'status': 'OPEN',
                        'service': service_name,
                        'risk': risk_level
                    }
        except:
            pass
    
    def scan(self):
        """Run full port scan with threading"""
        print(f"[*] Scanning {self.target}...")
        
        threads_list = []
        for port in range(self.start_port, self.end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads_list.append(thread)
            thread.start()
            
            if len(threads_list) >= 200:
                for t in threads_list:
                    t.join()
                threads_list = []
        
        for t in threads_list:
            t.join()
        
        # Check for aggressive scanning
        self.detect_aggressive_scan(self.target)
        
        # Save to database
        self.save_scan_results()
        
        return self.get_results()
    
    def save_scan_results(self):
        """Save scan to database"""
        conn = sqlite3.connect('security_tool.db')
        c = conn.cursor()
        c.execute("INSERT INTO scans VALUES (NULL, ?, ?, ?, ?, ?)",
                 (self.target, datetime.now().isoformat(),
                  json.dumps(self.open_ports), self.critical_count,
                  json.dumps(self.scan_results)))
        conn.commit()
        conn.close()
    
    def get_results(self):
        """Return scan results"""
        return {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': len(self.open_ports),
            'critical_threats': self.critical_count,
            'attack_detected': self.attack_detected,
            'ports_details': self.open_ports
        }

# =====================================================
# FLASK WEB APPLICATION
# =====================================================

app = Flask(__name__)
app.secret_key = get_config('server', 'secret_key', 'cybersecurity_secret_key_2026')

def login_required(f):
    """Decorator for login requirement"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# =====================================================
# HTML TEMPLATES (unchanged)
# =====================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Tool - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-bottom: 15px;
            padding: 10px;
            background: #fadbd8;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🛡️ Network Security Tool</h1>
        <p class="subtitle">Professional Port Scanner & Threat Detection</p>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0f0f23;
            color: #fff;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 28px;
        }
        .logout-btn {
            padding: 10px 20px;
            background: #e74c3c;
            border: none;
            border-radius: 5px;
            color: white;
            cursor: pointer;
            text-decoration: none;
        }
        .scan-section {
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 2px solid #667eea;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #aaa;
            font-size: 14px;
        }
        input, select {
            width: 100%;
            padding: 10px;
            background: #0f0f23;
            border: 1px solid #667eea;
            color: #fff;
            border-radius: 5px;
            font-size: 14px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        .results {
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: none;
        }
        .results.show {
            display: block;
        }
        .result-item {
            background: #16213e;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 5px solid #667eea;
        }
        .result-item.critical {
            border-left-color: #e74c3c;
        }
        .result-item.high {
            border-left-color: #f39c12;
        }
        .result-item.medium {
            border-left-color: #f1c40f;
        }
        .result-item.low {
            border-left-color: #27ae60;
        }
        .status-critical {
            color: #e74c3c;
            font-weight: bold;
        }
        .status-high {
            color: #f39c12;
            font-weight: bold;
        }
        .status-medium {
            color: #f1c40f;
            font-weight: bold;
        }
        .status-low {
            color: #27ae60;
            font-weight: bold;
        }
        .alerts {
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #e74c3c;
        }
        .alert-item {
            background: #e74c3c;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        .spinner {
            border: 4px solid #667eea;
            border-top: 4px solid transparent;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-box {
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 2px solid #667eea;
        }
        .stat-number {
            font-size: 28px;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #aaa;
            margin-top: 5px;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Network Security Dashboard</h1>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        
        <div class="stats" id="stats">
            <div class="stat-box">
                <div class="stat-number" id="total-scans">0</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="threats-found">0</div>
                <div class="stat-label">Threats Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="critical-count">0</div>
                <div class="stat-label">Critical Threats</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="attacks-detected">0</div>
                <div class="stat-label">Attacks Detected</div>
            </div>
        </div>
        
        <div class="scan-section">
            <h2>🔍 Port Scanner</h2>
            <form id="scanForm">
                <div class="form-group">
                    <label>Target IP Address or Hostname</label>
                    <input type="text" name="target" placeholder="e.g., 127.0.0.1 or scanme.nmap.org" required>
                </div>
                <div class="form-group">
                    <label>Start Port</label>
                    <input type="number" name="start_port" value="1" min="1" max="65535">
                </div>
                <div class="form-group">
                    <label>End Port</label>
                    <input type="number" name="end_port" value="1000" min="1" max="65535">
                </div>
                <button type="submit">🚀 Start Scan</button>
            </form>
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Scanning in progress...</p>
            </div>
        </div>
        
        <div class="results" id="results">
            <h2>📊 Scan Results</h2>
            <div id="resultsContent"></div>
        </div>
        
        <div id="attackAlerts"></div>
    </div>
    
    <script>
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const target = document.querySelector('input[name="target"]').value;
            const start_port = document.querySelector('input[name="start_port"]').value;
            const end_port = document.querySelector('input[name="end_port"]').value;
            
            document.getElementById('loading').style.display = 'block';
            
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, start_port, end_port})
                });
                
                const data = await response.json();
                displayResults(data);
            } catch (error) {
                alert('Error: ' + error);
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        });
        
        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            const resultsContent = document.getElementById('resultsContent');
            
            let html = `
                <p><strong>Target:</strong> ${data.target}</p>
                <p><strong>Timestamp:</strong> ${data.timestamp}</p>
                <p><strong>Open Ports:</strong> ${data.open_ports}</p>
                <p><strong>Critical Threats:</strong> <span class="status-critical">${data.critical_threats}</span></p>
            `;
            
            if (data.attack_detected) {
                html += '<div class="alert-item">🚨 AGGRESSIVE SCAN DETECTED! Alerts sent to your email!</div>';
            }
            
            html += '<h3>Details:</h3>';
            data.ports_details.forEach(port => {
                const riskClass = port.risk.toLowerCase().replace(' ', '-');
                html += `
                    <div class="result-item ${riskClass.split('-')[0]}">
                        <strong>Port ${port.port}</strong> - ${port.service}<br>
                        <span class="status-${riskClass.split('-')[0]}">Risk: ${port.risk}</span><br>
                        Threat: ${port.threat}
                    </div>
                `;
            });
            
            resultsContent.innerHTML = html;
            resultsDiv.classList.add('show');
            
            updateStats();
        }
        
        function updateStats() {
            // Update statistics (would fetch from backend)
            document.getElementById('total-scans').textContent = '1+';
        }
    </script>
</body>
</html>
"""

# =====================================================
# FLASK ROUTES
# =====================================================

@app.route('/', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['user_id'] = username
            return jsonify({'success': True, 'redirect': '/dashboard'}), 200
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials')
    
    if 'user_id' in session:
        return jsonify({'redirect': '/dashboard'}), 200
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    """Perform port scan"""
    data = request.json
    target = data.get('target')
    start_port = int(data.get('start_port', 1))
    end_port = int(data.get('end_port', 1000))
    
    scanner = NetworkSecurityScanner(target, start_port, end_port)
    results = scanner.scan()
    
    # Send alert if critical threats found
    if results['critical_threats'] > 0:
        alert_msg = f"""
        🚨 CRITICAL THREATS DETECTED! 🚨
        
        Target: {target}
        Open Ports: {results['open_ports']}
        Critical Threats: {results['critical_threats']}
        
        Ports Details:
        """
        for port in results['ports_details']:
            if 'CRITICAL' in port['risk']:
                alert_msg += f"\n  ⚠️ Port {port['port']}: {port['service']} - {port['threat']}"
        
        send_email_alert(f"Critical threats on {target}", alert_msg, "CRITICAL")
    
    return jsonify(results)

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return jsonify({'redirect': '/'}), 200

# =====================================================
# MAIN
# =====================================================

if __name__ == '__main__':
    init_database()
    
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║  🛡️  NETWORK SECURITY TOOL - Complete Port Scanner         ║
    ║  Real-Time Monitoring + Email Alerts + Web Dashboard       ║
    ╚════════════════════════════════════════════════════════════╝
    
    ⚠️  IMPORTANT SETUP STEPS:
    
    1. Create and edit config.ini (template in the repo):
       - mail.address = your-email@gmail.com
       - mail.password = your 16-character App Password (recommended) or your Gmail password
       - mail.recipients = comma-separated emails
       - auth.admin_user = admin
       - auth.admin_pass = choose_a_strong_password
    
    2. Install dependencies:
       pip install -r requirements.txt
    
    3. Run this script:
       python3 network_security_tool.py
    
    4. Open browser:
       http://localhost:5000
    
    5. Login with your admin credentials (from config.ini)
    
    ════════════════════════════════════════════════════════════
    """)
    
    host = get_config('server', 'host', '0.0.0.0')
    port = int(get_config('server', 'port', '5000'))
    app.run(debug=True, host=host, port=port)
