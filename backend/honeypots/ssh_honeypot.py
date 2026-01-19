#!/usr/bin/env python3
"""
SSH Honeypot - A fake SSH server for capturing attacker behavior
Designed for security research and threat intelligence gathering
"""

import socket
import threading
import paramiko
import json
import logging
from datetime import datetime
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HoneypotServer(paramiko.ServerInterface):
    """
    Implements the SSH server interface for the honeypot.
    Accepts all authentication attempts to capture credentials.
    """
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None
        self.password = None
    
    def check_auth_password(self, username, password):
        """
        Accept any username/password combination and log credentials.
        This allows us to see what attackers are trying.
        """
        self.username = username
        self.password = password
        logger.info(f"Auth attempt from {self.client_ip}: {username}:{password}")
        
        # Log the authentication attempt
        SessionLogger.log_auth(self.client_ip, username, password)
        
        # Always accept to allow session interaction
        return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_request(self, kind, chanid):
        """Allow session channel requests"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_pty_request(self, channel, term, width, height, 
                                   pixelwidth, pixelheight, modes):
        """Accept PTY (pseudo-terminal) requests"""
        return True
    
    def check_channel_shell_request(self, channel):
        """Accept shell requests"""
        self.event.set()
        return True
    
    def get_allowed_auths(self, username):
        """Specify that we support password authentication"""
        return 'password'


class FakeShell:
    """
    Simulates a realistic Linux shell environment.
    All responses are fake - no real system commands are executed.
    """
    
    def __init__(self, username='root'):
        self.username = username
        self.hostname = 'ubuntu-server'
        self.cwd = '/home/' + username
        
        # Fake filesystem structure for navigation
        self.filesystem = {
            '/': ['bin', 'etc', 'home', 'var', 'usr', 'tmp'],
            '/home': [username, 'admin', 'user'],
            f'/home/{username}': ['documents', 'downloads', '.bash_history', '.ssh'],
            f'/home/{username}/documents': ['passwords.txt', 'notes.txt'],
            '/etc': ['passwd', 'shadow', 'hosts', 'ssh'],
            '/var': ['log', 'www'],
        }
        
        # Fake file contents
        self.files = {
            '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n',
            '/etc/hosts': '127.0.0.1 localhost\n127.0.1.1 ubuntu-server\n',
            f'/home/{username}/.bash_history': 'ls -la\ncd documents\ncat passwords.txt\nexit\n',
            f'/home/{username}/documents/passwords.txt': 'mysql_password: notreal123\nssh_key_pass: fake_password\n',
        }
    
    def get_prompt(self):
        """Generate a realistic bash prompt"""
        return f"{self.username}@{self.hostname}:{self.cwd}$ "
    
    def execute_command(self, cmd):
        """
        Process commands and return fake but realistic output.
        No real system commands are executed for security.
        """
        cmd = cmd.strip()
        
        if not cmd:
            return ""
        
        parts = cmd.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Command implementations
        if command == 'ls':
            return self._cmd_ls(args)
        elif command == 'pwd':
            return self.cwd
        elif command == 'whoami':
            return self.username
        elif command == 'cat':
            return self._cmd_cat(args)
        elif command == 'uname':
            return self._cmd_uname(args)
        elif command == 'cd':
            return self._cmd_cd(args)
        elif command == 'help':
            return "Available commands: ls, pwd, whoami, cat, uname, cd, exit"
        elif command == 'exit':
            return None  # Signal to close session
        else:
            return f"-bash: {command}: command not found"
    
    def _cmd_ls(self, args):
        """Simulate ls command"""
        path = self.cwd
        if args and not args[0].startswith('-'):
            path = args[0] if args[0].startswith('/') else f"{self.cwd}/{args[0]}"
        
        # Normalize path
        path = path.rstrip('/')
        if not path:
            path = '/'
        
        if path in self.filesystem:
            return '  '.join(self.filesystem[path])
        else:
            return f"ls: cannot access '{path}': No such file or directory"
    
    def _cmd_cat(self, args):
        """Simulate cat command"""
        if not args:
            return "cat: missing file operand"
        
        filepath = args[0] if args[0].startswith('/') else f"{self.cwd}/{args[0]}"
        
        if filepath in self.files:
            return self.files[filepath]
        else:
            return f"cat: {args[0]}: No such file or directory"
    
    def _cmd_uname(self, args):
        """Simulate uname command"""
        if '-a' in args:
            return "Linux ubuntu-server 5.15.0-56-generic #62-Ubuntu SMP x86_64 GNU/Linux"
        return "Linux"
    
    def _cmd_cd(self, args):
        """Simulate cd command (basic implementation)"""
        if not args:
            self.cwd = f'/home/{self.username}'
            return ""
        
        new_path = args[0]
        if new_path.startswith('/'):
            target = new_path
        else:
            target = f"{self.cwd}/{new_path}".replace('//', '/')
        
        # Simple validation
        if target in self.filesystem or target.startswith('/home/'):
            self.cwd = target
            return ""
        else:
            return f"bash: cd: {new_path}: No such file or directory"


class SessionLogger:
    """
    Handles all logging operations for the honeypot.
    Stores data in JSON format for easy analysis.
    """
    
    LOG_FILE = 'honeypot_sessions.json'
    
    @staticmethod
    def log_auth(ip, username, password):
        """Log authentication attempts"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'type': 'authentication',
            'ip': ip,
            'username': username,
            'password': password
        }
        SessionLogger._write_log(data)
    
    @staticmethod
    def log_session(ip, username, commands, duration):
        """Log complete session information"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'type': 'session',
            'ip': ip,
            'username': username,
            'commands': commands,
            'duration_seconds': duration,
        }
        SessionLogger._write_log(data)
    
    @staticmethod
    def _write_log(data):
        """Append log entry to JSON file"""
        try:
            # Read existing logs
            if os.path.exists(SessionLogger.LOG_FILE):
                with open(SessionLogger.LOG_FILE, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            # Append new log
            logs.append(data)
            
            # Write back
            with open(SessionLogger.LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to write log: {e}")


def handle_client(client_socket, client_addr):
    """
    Handle individual SSH client connections.
    Manages the complete lifecycle of a honeypot session.
    """
    ip = client_addr[0]
    logger.info(f"New connection from {ip}")
    
    try:
        # Create SSH transport
        transport = paramiko.Transport(client_socket)
        
        # Generate host key (in production, load from file)
        host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)
        
        # Start SSH server
        server = HoneypotServer(ip)
        transport.start_server(server=server)
        
        # Wait for authentication
        channel = transport.accept(20)
        if channel is None:
            logger.warning(f"No channel from {ip}")
            return
        
        # Send welcome banner
        channel.send("Welcome to Ubuntu 22.04.1 LTS\r\n\r\n")
        
        # Initialize fake shell
        shell = FakeShell(server.username)
        channel.send(shell.get_prompt())
        
        # Track session
        commands = []
        start_time = datetime.now()
        buffer = ""
        
        # Main interaction loop
        while True:
            if channel.recv_ready():
                data = channel.recv(1024).decode('utf-8', errors='ignore')
                
                for char in data:
                    if char == '\r' or char == '\n':
                        if buffer.strip():
                            # Execute command
                            result = shell.execute_command(buffer)
                            commands.append(buffer.strip())
                            
                            if result is None:  # exit command
                                channel.send("\r\nLogout\r\n")
                                channel.close()
                                break
                            
                            if result:
                                channel.send(f"\r\n{result}\r\n")
                            channel.send(shell.get_prompt())
                            buffer = ""
                        else:
                            channel.send(shell.get_prompt())
                    elif char == '\x7f':  # Backspace
                        if buffer:
                            buffer = buffer[:-1]
                            channel.send('\b \b')
                    elif char == '\x03':  # Ctrl+C
                        channel.send("^C\r\n")
                        channel.send(shell.get_prompt())
                        buffer = ""
                    else:
                        buffer += char
                        channel.send(char)
            
            if not channel.active:
                break
        
        # Log session
        duration = (datetime.now() - start_time).total_seconds()
        SessionLogger.log_session(ip, server.username, commands, duration)
        logger.info(f"Session ended from {ip}, duration: {duration}s, commands: {len(commands)}")
        
    except Exception as e:
        logger.error(f"Error handling client {ip}: {e}")
    finally:
        try:
            transport.close()
        except:
            pass


def start_honeypot(host='0.0.0.0', port=2222):
    """
    Start the SSH honeypot server.
    Listens for connections and spawns handler threads.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(100)
        logger.info(f"SSH Honeypot listening on {host}:{port}")
        print(f"[+] Honeypot started on port {port}")
        print(f"[+] Logs will be saved to {SessionLogger.LOG_FILE}")
        print("[+] Press Ctrl+C to stop\n")
        
        while True:
            client_socket, client_addr = server_socket.accept()
            
            # Handle each client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[!] Shutting down honeypot...")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server_socket.close()
        logger.info("Honeypot stopped")


if __name__ == '__main__':
    # Ensure we're not running as root (security best practice)
    if os.geteuid() == 0:
        print("[!] WARNING: Running as root is not recommended")
        print("[!] Consider using a non-privileged user")
    
    start_honeypot()
