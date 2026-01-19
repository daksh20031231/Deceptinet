#!/usr/bin/env python3
"""
Enterprise HTTP Honeypot - Fake Admin Panel for Security Research
Captures web-based attacks including credential stuffing, SQL injection, and XSS
"""

from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os
import re
import hashlib
import uvicorn
from typing import Optional, Dict, List
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Enterprise Admin Portal", version="1.0.0")

# Add CORS middleware to accept requests from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# ATTACK PAYLOAD DETECTION ENGINE
# ============================================================================

class AttackDetector:
    """
    Detects common attack patterns in user input.
    Uses regex patterns to identify SQL injection, XSS, and other exploits.
    """
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
        r"(\bor\b\s+['\"]?true['\"]?)",
        r"(;.*drop\s+table)",
        r"(;.*delete\s+from)",
        r"(;.*insert\s+into)",
        r"(;.*update\s+.*set)",
        r"('|\")(\s*)(or|and)(\s*)('|\"|1|true)",
        r"(exec\s*\()",
        r"(execute\s+immediate)",
        r"(benchmark\s*\()",
        r"(sleep\s*\()",
        r"(waitfor\s+delay)",
        r"(--|\#|\/\*)",  # SQL comments
        r"(char\s*\()",
        r"(concat\s*\()",
        r"(0x[0-9a-f]+)",  # Hex encoding
    ]
    
    # XSS (Cross-Site Scripting) patterns
    XSS_PATTERNS = [
        r"(<script[^>]*>.*?</script>)",
        r"(<script[^>]*>)",
        r"(javascript:)",
        r"(onerror\s*=)",
        r"(onload\s*=)",
        r"(onclick\s*=)",
        r"(onmouseover\s*=)",
        r"(<iframe[^>]*>)",
        r"(<object[^>]*>)",
        r"(<embed[^>]*>)",
        r"(<img[^>]*onerror)",
        r"(<svg[^>]*onload)",
        r"(eval\s*\()",
        r"(alert\s*\()",
        r"(prompt\s*\()",
        r"(confirm\s*\()",
        r"(document\.cookie)",
        r"(document\.write)",
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"(\.\.\/|\.\.\\)",
        r"(%2e%2e%2f|%2e%2e/|..%2f|%2e%2e%5c)",
        r"(\/etc\/passwd)",
        r"(\/windows\/system32)",
    ]
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"(;\s*ls\s)",
        r"(;\s*cat\s)",
        r"(;\s*wget\s)",
        r"(;\s*curl\s)",
        r"(\|\s*nc\s)",
        r"(\&\&\s*id)",
        r"(`.*`)",
        r"(\$\(.*\))",
    ]
    
    @staticmethod
    def detect_sql_injection(text: str) -> List[str]:
        """Detect SQL injection patterns"""
        detected = []
        text_lower = text.lower()
        
        for pattern in AttackDetector.SQL_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                detected.append(f"SQL_INJECTION: {pattern}")
        
        return detected
    
    @staticmethod
    def detect_xss(text: str) -> List[str]:
        """Detect XSS patterns"""
        detected = []
        text_lower = text.lower()
        
        for pattern in AttackDetector.XSS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                detected.append(f"XSS: {pattern}")
        
        return detected
    
    @staticmethod
    def detect_path_traversal(text: str) -> List[str]:
        """Detect path traversal attempts"""
        detected = []
        
        for pattern in AttackDetector.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                detected.append(f"PATH_TRAVERSAL: {pattern}")
        
        return detected
    
    @staticmethod
    def detect_command_injection(text: str) -> List[str]:
        """Detect command injection attempts"""
        detected = []
        
        for pattern in AttackDetector.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                detected.append(f"COMMAND_INJECTION: {pattern}")
        
        return detected
    
    @staticmethod
    def analyze_payload(text: str) -> Dict:
        """Comprehensive payload analysis"""
        results = {
            'is_malicious': False,
            'attack_types': [],
            'patterns_detected': []
        }
        
        # Run all detectors
        sql_detections = AttackDetector.detect_sql_injection(text)
        xss_detections = AttackDetector.detect_xss(text)
        path_detections = AttackDetector.detect_path_traversal(text)
        cmd_detections = AttackDetector.detect_command_injection(text)
        
        # Aggregate results
        all_detections = sql_detections + xss_detections + path_detections + cmd_detections
        
        if all_detections:
            results['is_malicious'] = True
            results['patterns_detected'] = all_detections
            
            # Categorize attack types
            if sql_detections:
                results['attack_types'].append('SQL_INJECTION')
            if xss_detections:
                results['attack_types'].append('XSS')
            if path_detections:
                results['attack_types'].append('PATH_TRAVERSAL')
            if cmd_detections:
                results['attack_types'].append('COMMAND_INJECTION')
        
        return results


# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """
    Tracks request frequency per IP address.
    Detects automated attacks and brute force attempts.
    """
    
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[datetime]] = defaultdict(list)
    
    def is_rate_limited(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        # Clean old requests
        self.requests[ip] = [
            req_time for req_time in self.requests[ip]
            if req_time > cutoff
        ]
        
        # Check if over limit
        if len(self.requests[ip]) >= self.max_requests:
            return True
        
        # Add current request
        self.requests[ip].append(now)
        return False
    
    def get_request_count(self, ip: str) -> int:
        """Get current request count for IP"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        self.requests[ip] = [
            req_time for req_time in self.requests[ip]
            if req_time > cutoff
        ]
        
        return len(self.requests[ip])
    
    def get_stats(self, ip: str) -> Dict:
        """Get detailed stats for an IP"""
        count = self.get_request_count(ip)
        return {
            'request_count': count,
            'limit': self.max_requests,
            'window_seconds': self.window_seconds,
            'is_rate_limited': count >= self.max_requests
        }


# ============================================================================
# EVENT LOGGING
# ============================================================================

class EventLogger:
    """
    Handles structured logging of all honeypot events.
    Stores data in JSON format for analysis and threat intelligence.
    """
    
    LOG_FILE = 'honeypot_events.json'
    
    @staticmethod
    def log_event(event_type: str, data: Dict):
        """Log an event to JSON file"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'data': data
        }
        
        try:
            # Read existing events
            events = []
            if os.path.exists(EventLogger.LOG_FILE):
                with open(EventLogger.LOG_FILE, 'r') as f:
                    events = json.load(f)
            
            # Append new event
            events.append(event)
            
            # Write back
            with open(EventLogger.LOG_FILE, 'w') as f:
                json.dump(events, f, indent=2)
            
            logger.info(f"Logged {event_type} event from {data.get('ip', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
    
    @staticmethod
    def log_login_attempt(ip: str, username: str, password: str, 
                         user_agent: str, attack_analysis: Dict, 
                         rate_limit_info: Dict):
        """Log a login attempt with full context"""
        data = {
            'ip': ip,
            'username': username,
            'password': password,
            'user_agent': user_agent,
            'attack_analysis': attack_analysis,
            'rate_limit': rate_limit_info,
            'credential_hash': hashlib.md5(f"{username}:{password}".encode()).hexdigest()
        }
        EventLogger.log_event('login_attempt', data)
    
    @staticmethod
    def log_suspicious_request(ip: str, path: str, method: str, 
                               user_agent: str, attack_analysis: Dict):
        """Log suspicious/scanning requests"""
        data = {
            'ip': ip,
            'path': path,
            'method': method,
            'user_agent': user_agent,
            'attack_analysis': attack_analysis
        }
        EventLogger.log_event('suspicious_request', data)


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

rate_limiter = RateLimiter(max_requests=20, window_seconds=60)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_client_ip(request: Request) -> str:
    """Extract real client IP, handling proxies"""
    # Check for X-Forwarded-For header (common with proxies/load balancers)
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fall back to direct connection IP
    return request.client.host if request.client else 'unknown'


def analyze_user_agent(user_agent: str) -> Dict:
    """Analyze user agent for suspicious patterns"""
    analysis = {
        'raw': user_agent,
        'is_suspicious': False,
        'indicators': []
    }
    
    # Common attack tool user agents
    suspicious_keywords = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus',
        'burpsuite', 'metasploit', 'havij', 'acunetix',
        'w3af', 'webscarab', 'python-requests', 'curl',
        'wget', 'scanner', 'bot'
    ]
    
    ua_lower = user_agent.lower()
    for keyword in suspicious_keywords:
        if keyword in ua_lower:
            analysis['is_suspicious'] = True
            analysis['indicators'].append(f"Contains '{keyword}'")
    
    # Check for empty or very short user agents
    if len(user_agent) < 10:
        analysis['is_suspicious'] = True
        analysis['indicators'].append('Suspiciously short')
    
    return analysis


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve a basic homepage"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Enterprise Portal</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1 { color: #333; }
            a {
                color: #0066cc;
                text-decoration: none;
            }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Enterprise Portal</h1>
            <p>This is a corporate management system.</p>
            <ul>
                <li><a href="/admin/login">Admin Login</a></li>
                <li><a href="/docs">API Documentation</a></li>
            </ul>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    """Serve realistic admin login page"""
    ip = get_client_ip(request)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Log the access
    EventLogger.log_event('page_access', {
        'ip': ip,
        'path': '/admin/login',
        'user_agent': user_agent
    })
    
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login - Enterprise Portal</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
            }
            h2 {
                color: #333;
                margin-bottom: 30px;
                text-align: center;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 5px;
                color: #555;
                font-weight: 500;
            }
            input[type="text"],
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus,
            input[type="password"]:focus {
                outline: none;
                border-color: #667eea;
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
            .error-message {
                color: #d32f2f;
                background: #ffebee;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 20px;
                text-align: center;
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>🔐 Admin Portal</h2>
            <div id="errorMessage" class="error-message"></div>
            <form id="loginForm" method="POST" action="/admin/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const formData = new FormData(e.target);
                const errorDiv = document.getElementById('errorMessage');
                
                try {
                    const response = await fetch('/admin/login', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        errorDiv.style.display = 'none';
                        alert('Login successful!');
                        // In a real app, would redirect
                    } else {
                        errorDiv.textContent = data.detail || 'Login failed';
                        errorDiv.style.display = 'block';
                    }
                } catch (error) {
                    errorDiv.textContent = 'An error occurred. Please try again.';
                    errorDiv.style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.post("/admin/login")
async def admin_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """
    Process login attempts and capture credentials.
    Always returns realistic failure response to avoid detection.
    """
    ip = get_client_ip(request)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Check rate limiting
    rate_limit_info = rate_limiter.get_stats(ip)
    if rate_limiter.is_rate_limited(ip):
        logger.warning(f"Rate limit exceeded for {ip}")
        EventLogger.log_event('rate_limit_exceeded', {
            'ip': ip,
            'user_agent': user_agent,
            'stats': rate_limit_info
        })
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later."
        )
    
    # Analyze payloads for attacks
    username_analysis = AttackDetector.analyze_payload(username)
    password_analysis = AttackDetector.analyze_payload(password)
    
    combined_analysis = {
        'username': username_analysis,
        'password': password_analysis,
        'overall_malicious': (
            username_analysis['is_malicious'] or 
            password_analysis['is_malicious']
        )
    }
    
    # Analyze user agent
    ua_analysis = analyze_user_agent(user_agent)
    
    # Log the attempt
    EventLogger.log_login_attempt(
        ip=ip,
        username=username,
        password=password,
        user_agent=user_agent,
        attack_analysis=combined_analysis,
        rate_limit_info=rate_limit_info
    )
    
    # Log to console for real-time monitoring
    logger.warning(
        f"Login attempt from {ip} | "
        f"User: {username} | "
        f"Pass: {password[:20]}{'...' if len(password) > 20 else ''} | "
        f"Malicious: {combined_analysis['overall_malicious']} | "
        f"UA: {ua_analysis['is_suspicious']}"
    )
    
    # Always return realistic failure with slight delay
    import time
    time.sleep(1)  # Simulate database lookup
    
    # Return realistic error
    raise HTTPException(
        status_code=401,
        detail="Invalid username or password"
    )


@app.get("/admin/dashboard")
async def admin_dashboard(request: Request):
    """Fake dashboard endpoint to catch post-auth enumeration"""
    ip = get_client_ip(request)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    EventLogger.log_suspicious_request(
        ip=ip,
        path='/admin/dashboard',
        method='GET',
        user_agent=user_agent,
        attack_analysis={'unauthorized_access': True}
    )
    
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/api/users")
async def api_users(request: Request):
    """Fake API endpoint to attract automated scanners"""
    ip = get_client_ip(request)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    EventLogger.log_suspicious_request(
        ip=ip,
        path='/api/users',
        method='GET',
        user_agent=user_agent,
        attack_analysis={'api_enumeration': True}
    )
    
    # Return realistic but fake data
    return JSONResponse({
        "error": "Authentication required",
        "status": 401
    }, status_code=401)


@app.get("/stats")
async def get_stats():
    """
    Endpoint to view honeypot statistics (should be protected in production)
    """
    try:
        if not os.path.exists(EventLogger.LOG_FILE):
            return {"message": "No events logged yet"}
        
        with open(EventLogger.LOG_FILE, 'r') as f:
            events = json.load(f)
        
        # Calculate statistics
        stats = {
            'total_events': len(events),
            'event_types': {},
            'unique_ips': set(),
            'malicious_attempts': 0,
            'top_usernames': defaultdict(int),
            'attack_types': defaultdict(int)
        }
        
        for event in events:
            event_type = event['event_type']
            stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
            
            data = event['data']
            if 'ip' in data:
                stats['unique_ips'].add(data['ip'])
            
            if event_type == 'login_attempt':
                stats['top_usernames'][data['username']] += 1
                
                if data['attack_analysis']['overall_malicious']:
                    stats['malicious_attempts'] += 1
                    
                    for field in ['username', 'password']:
                        for attack_type in data['attack_analysis'][field].get('attack_types', []):
                            stats['attack_types'][attack_type] += 1
        
        # Convert sets to lists for JSON serialization
        stats['unique_ips'] = list(stats['unique_ips'])
        stats['unique_ip_count'] = len(stats['unique_ips'])
        stats['unique_ips'] = stats['unique_ips'][:10]  # Limit to top 10
        
        # Convert top usernames to list
        stats['top_usernames'] = dict(
            sorted(stats['top_usernames'].items(), 
                   key=lambda x: x[1], 
                   reverse=True)[:10]
        )
        
        stats['attack_types'] = dict(stats['attack_types'])
        
        return stats
        
    except Exception as e:
        logger.error(f"Error generating stats: {e}")
        return {"error": str(e)}


# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("HTTP Honeypot - Enterprise Admin Portal")
    print("=" * 60)
    print(f"Logs: {EventLogger.LOG_FILE}")
    print(f"Rate Limit: {rate_limiter.max_requests} req/{rate_limiter.window_seconds}s")
    print("\nEndpoints:")
    print("  - http://localhost:8000/admin/login (main honeypot)")
    print("  - http://localhost:8000/stats (statistics)")
    print("  - http://localhost:8000/docs (API docs)")
    print("\nPress Ctrl+C to stop")
    print("=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
