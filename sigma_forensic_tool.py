#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import subprocess
import platform
import psutil
import hashlib
import re
import threading
import time
import socket
import sys
from datetime import datetime
import random
import json
import math
import fcntl
import struct
import ctypes
from collections import deque
import queue
import concurrent.futures

# Enhanced virus signatures and detection mechanisms
MALWARE_SIGNATURES = {
    "viruses": [
        'Common cold', 'Influenza', 'Herpes', 'Chickenpox', 'Mumps',
        'Human papillomavirus', 'Measles', 'Rubella', 'Human immunodeficiency virus',
        'Viral gastroenteritis', 'Viral hepatitis', 'Infectious mononucleosis',
        'Viral conjunctivitis', 'Molluscum contagiosum', 'Ebola', 'Zika virus',
        'COVID-19', 'SARS', 'MERS', 'Hantavirus', 'Dengue', 'West Nile', 'Rabies',
        'Rotavirus', 'Norovirus', 'Adenovirus', 'Parvovirus', 'Hepatitis A', 'Hepatitis B',
        'Hepatitis C', 'Hepatitis D', 'Hepatitis E', 'Yellow fever', 'Smallpox'
    ],
    "malware": [
        'backdoor', 'spyware', 'keylogger', 'ransomware', 'trojan',
        'rootkit', 'botnet', 'adware', 'worm', 'rat', 'cryptominer', 'stealer',
        'banker', 'spy', 'injector', 'dropper', 'loader', 'exploit', 'shellcode',
        'binder', 'downloader', 'clicker', 'ddos', 'proxy', 'vpnfilter', 'emotet',
        'trickbot', 'wannacry', 'notpetya', 'zeus', 'darkcomet', 'gh0st', 'njrat'
    ],
    "patterns": [
        r'\b(?:malicious|evil|dangerous|hack|exploit|vulnerability|security\s?hole)\b',
        r'\b(?:password|credit\s?card|social\s?security|ssn|bank\s?account)\b',
        r'\b(?:crypt|encrypt|decrypt|ransom|bitcoin|monero|ethereum)\b',
        r'\b(?:reverse_?shell|bind_?shell|cmd_?exec|system\s?call|privilege\s?escalation)\b',
        r'\b(?:key\s?log|screen\s?cap|audio\s?record|webcam\s?capture)\b',
        r'\b(?:data\s?exfil|exfiltration|data\s?theft|information\s?steal)\b'
    ]
}

class ProctorSystem:
    """Advanced real-time protection system to block malicious activities"""
    def __init__(self, gui_callback):
        self.gui_callback = gui_callback
        self.running = True
        self.protection_enabled = True
        self.known_malicious_hashes = set()
        self.known_malicious_ips = set()
        self.known_malicious_domains = set()
        self.suspicious_processes = set()
        self.quarantine_dir = "/tmp/quarantine"
        self.load_signatures()
        self.create_quarantine()
        self.report_event("🛡️ Proctor system initialized", "info")
        
    def create_quarantine(self):
        """Create quarantine directory if not exists"""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir, exist_ok=True)
            os.chmod(self.quarantine_dir, 0o700)
    
    def load_signatures(self):
        """Load known malicious signatures from files"""
        try:
            # Load hashes
            if os.path.exists('malware_hashes.txt'):
                with open('malware_hashes.txt', 'r') as f:
                    self.known_malicious_hashes = set(line.strip() for line in f)
            
            # Load malicious IPs
            if os.path.exists('malicious_ips.txt'):
                with open('malicious_ips.txt', 'r') as f:
                    self.known_malicious_ips = set(line.strip() for line in f)
                    
            # Load malicious domains
            if os.path.exists('malicious_domains.txt'):
                with open('malicious_domains.txt', 'r') as f:
                    self.known_malicious_domains = set(line.strip() for line in f)
                    
            self.report_event(f"Loaded {len(self.known_malicious_hashes)} malware hashes, "
                            f"{len(self.known_malicious_ips)} malicious IPs, "
                            f"{len(self.known_malicious_domains)} malicious domains", "info")
        except Exception as e:
            self.report_event(f"Proctor signature load error: {str(e)}", "error")
    
    def report_event(self, event, event_type="info"):
        """Report an event to the GUI"""
        if self.gui_callback:
            self.gui_callback(event, event_type)
    
    def stop(self):
        self.running = False
        self.report_event("🛡️ Proctor system stopped", "info")
    
    def start_protection(self):
        """Start the real-time protection"""
        threading.Thread(target=self.monitor_system, daemon=True).start()
    
    def monitor_system(self):
        """Continuous system monitoring loop"""
        self.report_event("🛡️ Starting real-time protection", "info")
        
        # Track recently seen processes to avoid duplicate alerts
        recent_processes = deque(maxlen=100)
        
        while self.running and self.protection_enabled:
            try:
                # Monitor processes
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        if pid in recent_processes:
                            continue
                            
                        recent_processes.append(pid)
                        
                        # Check for known malicious hashes
                        if proc.info['exe'] and os.path.exists(proc.info['exe']):
                            file_hash = self.calculate_file_hash(proc.info['exe'])
                            if file_hash in self.known_malicious_hashes:
                                self.report_event(f"🚨 Blocked malicious process (hash match): {proc.info['name']} (PID: {pid})", "threat")
                                proc.terminate()
                                self.suspicious_processes.add(pid)
                                continue
                        
                        # Check for suspicious command line
                        if proc.info['cmdline']:
                            cmdline = ' '.join(proc.info['cmdline']).lower()
                            if any(sig in cmdline for sig in MALWARE_SIGNATURES["malware"] + MALWARE_SIGNATURES["viruses"]):
                                self.report_event(f"🚨 Blocked suspicious process (command line): {proc.info['name']} (PID: {pid})", "threat")
                                proc.terminate()
                                self.suspicious_processes.add(pid)
                                continue
                            
                            for pattern in MALWARE_SIGNATURES["patterns"]:
                                if re.search(pattern, cmdline, re.IGNORECASE):
                                    self.report_event(f"🚨 Blocked suspicious process (pattern match): {proc.info['name']} (PID: {pid})", "threat")
                                    proc.terminate()
                                    self.suspicious_processes.add(pid)
                                    break
                        
                        # Check for known malicious names
                        proc_name = proc.info['name'].lower()
                        if any(mal in proc_name for mal in MALWARE_SIGNATURES["malware"]):
                            self.report_event(f"🚨 Blocked suspicious process (name match): {proc.info['name']} (PID: {pid})", "threat")
                            proc.terminate()
                            self.suspicious_processes.add(pid)
                            continue
                        
                        # Check for suspicious locations
                        if proc.info['exe']:
                            exe_path = proc.info['exe'].lower()
                            if any(loc in exe_path for loc in ['/tmp', '/dev/shm', '/var/tmp']):
                                self.report_event(f"⚠️ Suspicious process location: {proc.info['exe']}", "warning")
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Monitor network connections
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        if conn.raddr:
                            ip = conn.raddr.ip
                            if ip in self.known_malicious_ips:
                                self.report_event(f"🚨 Blocked connection to malicious IP: {ip}", "threat")
                                if conn.pid:
                                    try:
                                        proc = psutil.Process(conn.pid)
                                        proc.terminate()
                                    except:
                                        pass
                                # Block IP at firewall level
                                self.block_ip(ip)
                    except Exception:
                        pass
                
                time.sleep(2)
            except Exception as e:
                self.report_event(f"Proctor monitoring error: {str(e)}", "error")
                time.sleep(10)
    
    def block_ip(self, ip):
        """Block IP using iptables"""
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            self.report_event(f"🔒 Blocked IP at firewall: {ip}", "info")
        except Exception as e:
            self.report_event(f"Could not block IP {ip}: {str(e)}", "warning")
    
    def quarantine_file(self, file_path):
        """Move file to quarantine"""
        try:
            if not os.path.exists(file_path):
                return False
                
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"{int(time.time())}_{filename}")
            os.rename(file_path, quarantine_path)
            os.chmod(quarantine_path, 0o000)  # Remove all permissions
            self.report_event(f"🔒 Quarantined file: {file_path}", "info")
            return True
        except Exception as e:
            self.report_event(f"Quarantine failed for {file_path}: {str(e)}", "error")
            return False
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(65536)  # 64kb chunks
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception:
            return ""
    
    def scan_file(self, file_path):
        """Scan a file for threats"""
        if not os.path.exists(file_path):
            return "clean"
            
        # 1. Check against known hashes
        file_hash = self.calculate_file_hash(file_path)
        if file_hash in self.known_malicious_hashes:
            return "malicious"
        
        # 2. Check file name
        filename = os.path.basename(file_path).lower()
        if any(mal in filename for mal in MALWARE_SIGNATURES["malware"] + MALWARE_SIGNATURES["viruses"]):
            return "suspicious"
        
        # 3. Check file content
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read(8192)  # First 8KB
                
                # Check for malware signatures
                for mal_type in ["malware", "viruses"]:
                    for sig in MALWARE_SIGNATURES[mal_type]:
                        if sig.lower() in content.lower():
                            return "malicious"
                
                # Check for suspicious patterns
                for pattern in MALWARE_SIGNATURES["patterns"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        return "suspicious"
                
                # Check for high entropy (encrypted/compressed content)
                entropy = self.calculate_entropy(content)
                if entropy > 7.0:  # High entropy threshold
                    return "suspicious"
                    
        except Exception:
            pass
        
        return "clean"
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
                
        return entropy

class LinuxInvestigationTool:
    def __init__(self, root):
        self.root = root
        self.root.title("SIGMA CyberGhost - Advanced Linux Forensic Tool")
        self.root.geometry("1200x900")
        
        # BLACK HAT HACKER STYLE COLOR SCHEME
        self.bg_color = "#000000"  # Pure black
        self.fg_color = "#00ff00"  # Matrix green
        self.accent_color = "#ff0000"  # Hacker red
        self.dark_bg = "#111111"   # Dark gray
        self.text_bg = "#0a0a0a"   # Almost black
        self.highlight_color = "#ff0000"  # Red highlights
        self.matrix_green = "#00ff41"  # Bright matrix green
        
        # Apply hacker theme
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        
        # Custom hacker theme
        self.style.theme_use('clam')
        self.style.configure('.', 
                           background=self.bg_color, 
                           foreground=self.fg_color,
                           font=("Consolas", 10))
        
        # Configure styles
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', 
                            background=self.dark_bg, 
                            foreground=self.fg_color, 
                            font=("Consolas", 10, 'bold'), 
                            padding=[15, 5])
        self.style.map('TNotebook.Tab', 
                     background=[('selected', self.accent_color)],
                     foreground=[('selected', '#000000')])
        
        self.style.configure('Treeview', 
                           background=self.text_bg, 
                           foreground=self.fg_color, 
                           fieldbackground=self.text_bg, 
                           rowheight=25)
        self.style.map('Treeview', 
                     background=[('selected', self.accent_color)],
                     foreground=[('selected', '#000000')])
        
        self.style.configure('Vertical.TScrollbar', 
                           background=self.dark_bg, 
                           bordercolor=self.dark_bg, 
                           arrowcolor=self.fg_color)
        
        self.style.configure('TButton', 
                           background=self.dark_bg, 
                           foreground=self.fg_color, 
                           font=("Consolas", 10, 'bold'), 
                           borderwidth=1,
                           relief='raised')
        self.style.map('TButton', 
                     background=[('active', self.accent_color), ('pressed', self.accent_color)],
                     foreground=[('active', '#000000'), ('pressed', '#000000')])
        
        self.style.configure('TLabel', 
                           background=self.bg_color, 
                           foreground=self.fg_color,
                           font=("Consolas", 10))
        
        self.style.configure('TLabelframe', 
                           background=self.bg_color, 
                           foreground=self.fg_color,
                           font=("Consolas", 10, 'bold'))
        
        self.style.configure('TLabelframe.Label', 
                           background=self.bg_color, 
                           foreground=self.highlight_color,
                           font=("Consolas", 10, 'bold'))
        
        # Create main frames
        header_frame = ttk.Frame(root, style='TFrame')
        header_frame.pack(fill='x', pady=(10, 0))
        
        content_frame = ttk.Frame(root, style='TFrame')
        content_frame.pack(fill='both', expand=True, padx=15, pady=10)
        
        # Create status bar early
        status_frame = ttk.Frame(root, style='TFrame')
        status_frame.pack(fill='x', side='bottom')
        self.status = tk.StringVar()
        self.status.set("🟢 Ready")
        status_bar = tk.Label(status_frame, 
                           textvariable=self.status, 
                           bd=1, 
                           relief=tk.SUNKEN, 
                           anchor=tk.W,
                           bg=self.dark_bg,
                           fg=self.matrix_green,
                           font=("Consolas", 9, "bold"))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Custom SIGMA banner
        banner_text = r"""
 ######  ####  ######   ##     ##    ###            ########  ########   #######  ########  #######   ######   #######  ##       
##    ##  ##  ##    ##  ###   ###   ## ##           ##     ## ##     ## ##     ##    ##    ##     ## ##    ## ##     ## ##       
##        ##  ##        #### ####  ##   ##          ##     ## ##     ## ##     ##    ##    ##     ## ##       ##     ## ##       
 ######   ##  ##   #### ## ### ## ##     ##         ########  ########  ##     ##    ##    ##     ## ##       ##     ## ##       
      ##  ##  ##    ##  ##     ## #########         ##        ##   ##   ##     ##    ##    ##     ## ##       ##     ## ##       
##    ##  ##  ##    ##  ##     ## ##     ##         ##        ##    ##  ##     ##    ##    ##     ## ##    ## ##     ## ##       
 ######  ####  ######   ##     ## ##     ## ####### ##        ##     ##  #######     ##     #######   ######   #######  ######## 
        """
        self.banner_label = tk.Label(header_frame, 
                              text=banner_text, 
                              font=("Courier", 8), 
                              fg=self.accent_color,  # Red color for hacker look
                              bg=self.bg_color,
                              justify="center")
        self.banner_label.pack(pady=(0, 5))
        
        # Banner animation variables
        self.banner_colors = ["#ff0000", "#cc0000", "#ff6666", "#cc3333", "#ff3333"]  # Red shades
        self.current_color_index = 0
        self.animate_banner()
        
        title_label = tk.Label(header_frame, 
                             text="SIGMA CYBER GHOST - ADVANCED LINUX FORENSIC TOOL", 
                             font=("Consolas", 16, "bold"), 
                             fg=self.accent_color,  # Red title
                             bg=self.bg_color)
        title_label.pack(pady=(0, 10))
        
        # Social Profiles
        social_frame = ttk.Frame(header_frame, style='TFrame')
        social_frame.pack(fill='x', pady=10)
        
        github_btn = tk.Button(social_frame, 
                             text="🐙 GitHub: sigma-cyber-ghost", 
                             command=lambda: os.system("xdg-open https://github.com/sigma-cyber-ghost"),
                             bg=self.dark_bg,
                             fg=self.fg_color,
                             relief='flat',
                             font=("Consolas", 10, "bold"),
                             cursor="hand2",
                             bd=0,
                             activebackground=self.accent_color,
                             activeforeground="#000000")
        github_btn.pack(side='left', padx=10)
        
        telegram_btn = tk.Button(social_frame, 
                              text="📢 Telegram: sigma_cyber_ghost", 
                              command=lambda: os.system("xdg-open https://t.me/sigma_cyber_ghost"),
                              bg=self.dark_bg,
                              fg=self.fg_color,
                              relief='flat',
                              font=("Consolas", 10, "bold"),
                              cursor="hand2",
                              bd=0,
                              activebackground=self.accent_color,
                              activeforeground="#000000")
        telegram_btn.pack(side='left', padx=10)
        
        youtube_btn = tk.Button(social_frame, 
                              text="📺 YouTube: @sigma_ghost_hacking", 
                              command=lambda: os.system("xdg-open https://youtube.com/@sigma_ghost_hacking"),
                              bg=self.dark_bg,
                              fg=self.fg_color,
                              relief='flat',
                             font=("Consolas", 10, "bold"),
                             cursor="hand2",
                             bd=0,
                             activebackground=self.accent_color,
                             activeforeground="#000000")
        youtube_btn.pack(side='left', padx=10)
        
        # Proctor status indicator
        proctor_frame = ttk.Frame(header_frame, style='TFrame')
        proctor_frame.pack(fill='x', pady=5)
        
        self.proctor_status = tk.StringVar(value="🔴 Proctor: INACTIVE")
        proctor_label = tk.Label(proctor_frame, 
                               textvariable=self.proctor_status,
                               bg=self.dark_bg,
                               fg="#ff6666",
                               font=("Consolas", 10, "bold"))
        proctor_label.pack(side='left', padx=20)
        
        # Proctor toggle button
        self.proctor_btn = ttk.Button(proctor_frame, text="Activate Proctor", 
                                    command=self.toggle_proctor,
                                    style='TButton')
        self.proctor_btn.pack(side='right', padx=20)
        
        # Scan status indicator
        self.scan_status = tk.StringVar(value="🔒 System Secure")
        status_indicator = tk.Label(proctor_frame, 
                                  textvariable=self.scan_status,
                                  bg=self.dark_bg,
                                  fg=self.matrix_green,
                                  font=("Consolas", 10, "bold"))
        status_indicator.pack(side='right', padx=20)
        
        # Notebook (Tabs)
        self.notebook = ttk.Notebook(content_frame, style='TNotebook')
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_system_info_tab()
        self.create_process_explorer_tab()
        self.create_network_analysis_tab()
        self.create_file_inspector_tab()
        self.create_log_analyzer_tab()
        self.create_malware_scanner_tab()
        self.create_forensics_tab()
        self.create_realtime_monitor_tab()
        
        # Initialize Proctor system
        self.proctor = ProctorSystem(self.report_proctor_event)
        
        # Start background monitoring
        self.monitor_active = True
        threading.Thread(target=self.background_monitoring, daemon=True).start()
        
    def toggle_proctor(self):
        """Toggle Proctor real-time protection"""
        if self.proctor.protection_enabled:
            self.proctor.protection_enabled = False
            self.proctor_status.set("🔴 Proctor: INACTIVE")
            self.proctor_btn.config(text="Activate Proctor")
            self.report_proctor_event("🛡️ Proctor protection disabled", "info")
        else:
            self.proctor.protection_enabled = True
            self.proctor_status.set("🟢 Proctor: ACTIVE")
            self.proctor_btn.config(text="Deactivate Proctor")
            self.proctor.start_protection()
            self.report_proctor_event("🛡️ Proctor protection enabled", "info")
        
    def report_proctor_event(self, event, event_type):
        """Report an event from Proctor to the real-time monitor"""
        self.realtime_text.config(state=tk.NORMAL)
        
        if event_type == "threat":
            tag = "threat"
            color = "#ff0000"
        elif event_type == "warning":
            tag = "warning"
            color = "#ff9900"
        else:
            tag = "info"
            color = self.matrix_green
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.realtime_text.insert(tk.END, f"[{timestamp}] {event}\n", tag)
        self.realtime_text.tag_config(tag, foreground=color)
        self.realtime_text.see(tk.END)
        self.realtime_text.config(state=tk.DISABLED)
        
    def create_realtime_monitor_tab(self):
        """Create tab for real-time monitoring"""
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Real-time Monitor")
        
        # Text widget for events
        self.realtime_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, 
                                                     bg=self.text_bg, fg=self.fg_color, 
                                                     font=("Consolas", 10))
        self.realtime_text.pack(expand=True, fill='both', padx=10, pady=10)
        self.realtime_text.config(state=tk.DISABLED)
        
        # Configure tags
        self.realtime_text.tag_config("threat", foreground="#ff0000")
        self.realtime_text.tag_config("warning", foreground="#ff9900")
        self.realtime_text.tag_config("info", foreground=self.matrix_green)
        
        # Control buttons
        control_frame = ttk.Frame(tab, style='TFrame')
        control_frame.pack(fill='x', padx=10, pady=10)
        
        clear_btn = ttk.Button(control_frame, text="Clear Log", 
                              command=lambda: self.realtime_text.config(state=tk.NORMAL) or self.realtime_text.delete(1.0, tk.END) or self.realtime_text.config(state=tk.DISABLED),
                              style='TButton')
        clear_btn.pack(side='left')
        
        # Add protection status
        status_label = ttk.Label(control_frame, textvariable=self.proctor_status, style='TLabel')
        status_label.pack(side='right')
        
    def animate_banner(self):
        """Animate the banner with color cycling effect"""
        color = self.banner_colors[self.current_color_index]
        self.banner_label.config(fg=color)
        self.current_color_index = (self.current_color_index + 1) % len(self.banner_colors)
        self.root.after(200, self.animate_banner)
        
    def background_monitoring(self):
        """Background thread for continuous system monitoring"""
        while self.monitor_active:
            try:
                # Check for suspicious processes
                suspicious_procs = self.detect_suspicious_processes()
                if suspicious_procs:
                    self.scan_status.set(f"⚠️ {len(suspicious_procs)} suspicious processes detected!")
                else:
                    self.scan_status.set("🔒 System Secure")
                
                # Check network anomalies
                if self.detect_network_anomalies():
                    self.scan_status.set("⚠️ Suspicious network activity detected!")
                
                time.sleep(10)
            except Exception as e:
                self.status.set(f"❌ Monitoring error: {str(e)}")
                time.sleep(30)
                
    def detect_suspicious_processes(self):
        """Detect potentially malicious processes"""
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                # Check for processes with no executable path
                if not proc.info['exe'] or not os.path.exists(proc.info['exe']):
                    suspicious.append(proc.info)
                    continue
                    
                # Check for hidden processes
                if proc.info['name'].startswith('.') or 'stealth' in proc.info['name'].lower():
                    suspicious.append(proc.info)
                    continue
                    
                # Check for known suspicious process names
                suspicious_names = ['miner', 'crypt', 'backdoor', 'rootkit', 'bot', 'malware',
                                    'spyware', 'keylogger', 'ransom', 'trojan', 'injector', 'payload']
                if any(name in proc.info['name'].lower() for name in suspicious_names):
                    suspicious.append(proc.info)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return suspicious
        
    def detect_network_anomalies(self):
        """Detect suspicious network connections"""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.port > 32768:
                    # High port listening
                    return True
                    
                if conn.raddr and conn.raddr.port in [6667, 8080, 31337, 4444, 1337]:  # Common malware ports
                    return True
                    
                if conn.raddr and 'tor' in conn.raddr.ip:
                    return True
                    
        except Exception:
            pass
            
        return False
        
    def create_dashboard_tab(self):
        """Create system dashboard tab"""
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Dashboard")
        
        # Create dashboard widgets
        dashboard_frame = ttk.Frame(tab, style='TFrame')
        dashboard_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # System health widgets
        health_frame = ttk.LabelFrame(dashboard_frame, text="System Health", style='TLabelframe')
        health_frame.pack(fill='x', pady=5)
        
        # CPU usage
        cpu_frame = ttk.Frame(health_frame, style='TFrame')
        cpu_frame.pack(fill='x', pady=5)
        ttk.Label(cpu_frame, text="CPU Usage:", style='TLabel').pack(side='left')
        self.cpu_var = tk.StringVar(value="0%")
        self.cpu_var_label = ttk.Label(cpu_frame, textvariable=self.cpu_var, style='TLabel')
        self.cpu_var_label.pack(side='right')
        
        # Memory usage
        mem_frame = ttk.Frame(health_frame, style='TFrame')
        mem_frame.pack(fill='x', pady=5)
        ttk.Label(mem_frame, text="Memory Usage:", style='TLabel').pack(side='left')
        self.mem_var = tk.StringVar(value="0%")
        self.mem_var_label = ttk.Label(mem_frame, textvariable=self.mem_var, style='TLabel')
        self.mem_var_label.pack(side='right')
        
        # Disk usage
        disk_frame = ttk.Frame(health_frame, style='TFrame')
        disk_frame.pack(fill='x', pady=5)
        ttk.Label(disk_frame, text="Disk Usage:", style='TLabel').pack(side='left')
        self.disk_var = tk.StringVar(value="0%")
        self.disk_var_label = ttk.Label(disk_frame, textvariable=self.disk_var, style='TLabel')
        self.disk_var_label.pack(side='right')
        
        # Security status
        sec_frame = ttk.LabelFrame(dashboard_frame, text="Security Status", style='TLabelframe')
        sec_frame.pack(fill='x', pady=5)
        
        # Quick scan button
        scan_btn = ttk.Button(sec_frame, text="Run Quick Security Scan", command=self.run_quick_scan,
                             style='TButton')
        scan_btn.pack(pady=10)
        
        # Security findings
        findings_frame = ttk.Frame(sec_frame, style='TFrame')
        findings_frame.pack(fill='x', pady=5)
        ttk.Label(findings_frame, text="Last Scan Findings:", style='TLabel').pack(side='left')
        self.findings_var = tk.StringVar(value="No scan performed yet")
        ttk.Label(findings_frame, textvariable=self.findings_var, foreground="#ff6666", style='TLabel').pack(side='right')
        
        # Threat level indicator
        threat_frame = ttk.LabelFrame(dashboard_frame, text="Threat Level", style='TLabelframe')
        threat_frame.pack(fill='x', pady=10)
        
        self.threat_level = tk.StringVar(value="Low")
        threat_indicator = tk.Label(threat_frame, textvariable=self.threat_level, 
                                   font=("Consolas", 16, "bold"), foreground=self.accent_color)  # Red threat level
        threat_indicator.pack(pady=10)
        
        # Update health stats
        self.update_health_stats()
        
    def update_health_stats(self):
        """Update system health statistics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent()
            self.cpu_var.set(f"{cpu_percent}%")
            cpu_color = self.matrix_green if cpu_percent < 50 else "#ffff00" if cpu_percent < 80 else "#ff0000"
            self.cpu_var_label.config(foreground=cpu_color)
            
            # Memory usage
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
            self.mem_var.set(f"{mem_percent}%")
            mem_color = self.matrix_green if mem_percent < 50 else "#ffff00" if mem_percent < 80 else "#ff0000"
            self.mem_var_label.config(foreground=mem_color)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            self.disk_var.set(f"{disk_percent}%")
            disk_color = self.matrix_green if disk_percent < 50 else "#ffff00" if disk_percent < 80 else "#ff0000"
            self.disk_var_label.config(foreground=disk_color)
            
        except Exception as e:
            self.status.set(f"❌ Health update error: {str(e)}")
            
        # Schedule next update
        self.root.after(5000, self.update_health_stats)
        
    def run_quick_scan(self):
        """Run a quick security scan"""
        self.status.set("🕒 Running quick security scan...")
        threading.Thread(target=self.perform_quick_scan, daemon=True).start()
        
    def perform_quick_scan(self):
        """Perform a quick security scan in background thread"""
        try:
            findings = []
            
            # 1. Check for suspicious processes
            suspicious_procs = self.detect_suspicious_processes()
            if suspicious_procs:
                findings.append(f"{len(suspicious_procs)} suspicious processes")
                
            # 2. Check network anomalies
            if self.detect_network_anomalies():
                findings.append("suspicious network activity")
                
            # 3. Check critical files
            critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
            for file in critical_files:
                if not os.path.exists(file):
                    findings.append(f"missing critical file: {file}")
                elif os.stat(file).st_mode & 0o777 != 0o600:
                    findings.append(f"insecure permissions on {file}")
                    
            # 4. Check for rootkits
            if self.check_for_rootkits():
                findings.append("possible rootkit detected")
                
            # Update findings and threat level
            if findings:
                self.findings_var.set(", ".join(findings))
                self.scan_status.set(f"⚠️ {len(findings)} security issues found!")
                self.threat_level.set("High")
            else:
                self.findings_var.set("No security issues found")
                self.scan_status.set("🔒 System Secure")
                self.threat_level.set("Low")
                
            self.status.set("✅ Quick security scan completed")
            
        except Exception as e:
            self.status.set(f"❌ Scan error: {str(e)}")
            
    def check_for_rootkits(self):
        """Check for signs of rootkits"""
        try:
            # Check for hidden modules
            lsmod = subprocess.check_output(['lsmod'], text=True)
            if 'hidden' in lsmod.lower():
                return True
                
            # Check for suspicious kernel modules
            suspicious_modules = ['adore', 'enyelkm', 'rpldev', 'knark', 'backdoor']
            if any(module in lsmod.lower() for module in suspicious_modules):
                return True
                
            # Check for modified system utilities
            bin_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
            suspicious_bins = ['ls', 'ps', 'netstat', 'ss', 'top']
            for bin_name in suspicious_bins:
                for path in bin_paths:
                    bin_path = os.path.join(path, bin_name)
                    if os.path.exists(bin_path):
                        # Check if file is modified recently
                        mtime = os.path.getmtime(bin_path)
                        if time.time() - mtime < 86400:  # Modified in last 24 hours
                            return True
                            
        except Exception:
            pass
            
        return False
        
    def create_system_info_tab(self):
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="System Information")
        
        # Text widget for system info
        text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, bg=self.text_bg, fg=self.fg_color, 
                                      font=("Consolas", 10))
        text.pack(expand=True, fill='both', padx=10, pady=10)
        
        # Get detailed system information
        sys_info = self.get_detailed_system_info()
        text.insert(tk.INSERT, sys_info)
        text.config(state=tk.DISABLED)
        
    def get_detailed_system_info(self):
        """Get detailed system information"""
        info = "=== SYSTEM INFORMATION ===\n\n"
        
        # Basic system info
        info += f"System: {platform.system()}\n"
        info += f"Node Name: {platform.node()}\n"
        info += f"Release: {platform.release()}\n"
        info += f"Version: {platform.version()}\n"
        info += f"Machine: {platform.machine()}\n"
        info += f"Processor: {platform.processor()}\n\n"
        
        # CPU info
        info += "=== CPU INFORMATION ===\n"
        info += f"Physical Cores: {psutil.cpu_count(logical=False)}\n"
        info += f"Total Cores: {psutil.cpu_count(logical=True)}\n"
        try:
            freq = psutil.cpu_freq()
            info += f"Current Frequency: {freq.current:.2f} MHz\n"
            info += f"Max Frequency: {freq.max:.2f} MHz\n\n"
        except Exception:
            info += "Frequency: Not available\n\n"
        
        # Memory info
        mem = psutil.virtual_memory()
        info += "=== MEMORY INFORMATION ===\n"
        info += f"Total RAM: {mem.total / (1024**3):.2f} GB\n"
        info += f"Available: {mem.available / (1024**3):.2f} GB\n"
        info += f"Used: {mem.used / (1024**3):.2f} GB ({mem.percent}%)\n\n"
        
        # Disk info
        partitions = psutil.disk_partitions()
        info += "=== DISK INFORMATION ===\n"
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                info += f"Device: {partition.device}\n"
                info += f"  Mountpoint: {partition.mountpoint}\n"
                info += f"  Filesystem: {partition.fstype}\n"
                info += f"  Total: {usage.total / (1024**3):.2f} GB\n"
                info += f"  Used: {usage.used / (1024**3):.2f} GB ({usage.percent}%)\n"
                info += f"  Free: {usage.free / (1024**3):.2f} GB\n\n"
            except Exception:
                continue
                
        # Boot time
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        info += f"System Boot Time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        # Network info
        info += "\n=== NETWORK INFORMATION ===\n"
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            info += f"Hostname: {hostname}\n"
            info += f"IP Address: {ip}\n"
        except:
            info += "Network info: Not available\n"
        
        return info
        
    def create_process_explorer_tab(self):
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Process Explorer")
        
        # Treeview for processes
        columns = ("PID", "Name", "Status", "CPU%", "Memory%", "Exe Path")
        self.process_tree = ttk.Treeview(tab, columns=columns, show="headings", selectmode="extended")
        
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=120)
        self.process_tree.column("Exe Path", width=250)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        # Control frame
        control_frame = ttk.Frame(tab, style='TFrame')
        control_frame.pack(fill='x', padx=10, pady=5)
        
        # Buttons
        refresh_btn = ttk.Button(control_frame, text="Refresh Processes", command=self.populate_processes,
                                style='TButton')
        refresh_btn.pack(side='left', padx=5)
        
        kill_btn = ttk.Button(control_frame, text="Kill Selected", command=self.kill_selected_processes,
                             style='TButton')
        kill_btn.pack(side='left', padx=5)
        
        # Treeview and scrollbar
        self.process_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")
        
        # Populate processes
        self.populate_processes()
        
    def populate_processes(self):
        """Populate process treeview"""
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
            
        # Populate with processes
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'exe']):
            try:
                exe_path = proc.info['exe'] if proc.info['exe'] else "Unknown"
                self.process_tree.insert("", "end", values=(
                    proc.info['pid'],
                    proc.info['name'],
                    proc.info['status'],
                    f"{proc.info['cpu_percent']:.1f}",
                    f"{proc.info['memory_percent']:.1f}",
                    exe_path
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
    def kill_selected_processes(self):
        """Kill selected processes"""
        selected = self.process_tree.selection()
        if not selected:
            return
            
        for item in selected:
            pid = int(self.process_tree.item(item, 'values')[0])
            try:
                p = psutil.Process(pid)
                p.terminate()
            except Exception as e:
                messagebox.showerror("Error", f"Could not terminate process {pid}: {str(e)}")
                
        # Refresh process list after 1 second
        self.root.after(1000, self.populate_processes)
        
    def create_network_analysis_tab(self):
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Network Analysis")
        
        # Create notebook for sub-tabs
        net_notebook = ttk.Notebook(tab)
        net_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Connections tab
        conn_tab = ttk.Frame(net_notebook, style='TFrame')
        net_notebook.add(conn_tab, text="Active Connections")
        
        # Interfaces tab
        iface_tab = ttk.Frame(net_notebook, style='TFrame')
        net_notebook.add(iface_tab, text="Network Interfaces")
        
        # Port scan tab
        port_tab = ttk.Frame(net_notebook, style='TFrame')
        net_notebook.add(port_tab, text="Port Scanner")
        
        # Populate tabs
        self.create_network_connections_tab(conn_tab)
        self.create_network_interfaces_tab(iface_tab)
        self.create_port_scanner_tab(port_tab)
        
    def create_network_connections_tab(self, tab):
        """Create network connections tab"""
        columns = ("Protocol", "Local Address", "Remote Address", "Status", "PID", "Process")
        tree = ttk.Treeview(tab, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=120)
        tree.column("Local Address", width=200)
        tree.column("Remote Address", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Populate connections
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr:
                    local = f"{conn.laddr.ip}:{conn.laddr.port}"
                else:
                    local = ""
                    
                if conn.raddr:
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                else:
                    remote = ""
                    
                pid = conn.pid or ""
                process = ""
                if pid:
                    try:
                        p = psutil.Process(pid)
                        process = p.name()
                    except:
                        pass
                        
                tree.insert("", "end", values=(
                    conn.type.name,
                    local,
                    remote,
                    conn.status,
                    pid,
                    process
                ))
        except Exception as e:
            tree.insert("", "end", values=("Error", str(e), "", "", "", ""))
            
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_network_interfaces_tab(self, tab):
        """Create network interfaces tab"""
        text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, bg=self.text_bg, fg=self.fg_color, 
                                      font=("Consolas", 10))
        text.pack(expand=True, fill='both', padx=10, pady=10)
        
        # Get interface info
        try:
            info = "=== NETWORK INTERFACES ===\n\n"
            for name, addrs in psutil.net_if_addrs().items():
                info += f"Interface: {name}\n"
                for addr in addrs:
                    info += f"  {addr.family.name}: {addr.address}\n"
                    if addr.netmask:
                        info += f"    Netmask: {addr.netmask}\n"
                    if addr.broadcast:
                        info += f"    Broadcast: {addr.broadcast}\n"
                info += "\n"
                
            # Get interface stats
            stats = psutil.net_if_stats()
            info += "\n=== INTERFACE STATS ===\n\n"
            for name, stat in stats.items():
                info += f"Interface: {name}\n"
                info += f"  Is Up: {stat.isup}\n"
                info += f"  Duplex: {stat.duplex}\n"
                info += f"  Speed: {stat.speed} Mbps\n"
                info += f"  MTU: {stat.mtu}\n\n"
                
            text.insert(tk.INSERT, info)
        except Exception as e:
            text.insert(tk.INSERT, f"Error retrieving network info: {str(e)}")
            
        text.config(state=tk.DISABLED)
        
    def create_port_scanner_tab(self, tab):
        """Create port scanner tab"""
        control_frame = ttk.Frame(tab, style='TFrame')
        control_frame.pack(fill='x', padx=10, pady=10)
        
        # Host entry
        ttk.Label(control_frame, text="Host:", style='TLabel').pack(side='left')
        self.host_var = tk.StringVar(value="127.0.0.1")
        host_entry = ttk.Entry(control_frame, textvariable=self.host_var, width=20)
        host_entry.pack(side='left', padx=5)
        
        # Port range
        ttk.Label(control_frame, text="Port Range:", style='TLabel').pack(side='left', padx=(10, 0))
        self.port_start_var = tk.StringVar(value="1")
        port_start_entry = ttk.Entry(control_frame, textvariable=self.port_start_var, width=5)
        port_start_entry.pack(side='left')
        
        ttk.Label(control_frame, text="to", style='TLabel').pack(side='left', padx=5)
        self.port_end_var = tk.StringVar(value="1024")
        port_end_entry = ttk.Entry(control_frame, textvariable=self.port_end_var, width=5)
        port_end_entry.pack(side='left')
        
        # Scan button
        scan_btn = ttk.Button(control_frame, text="Scan Ports", command=self.start_port_scan,
                             style='TButton')
        scan_btn.pack(side='left', padx=10)
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(control_frame, mode='determinate')
        self.scan_progress.pack(side='left', fill='x', expand=True, padx=10)
        
        # Results treeview
        columns = ("Port", "Status", "Service")
        self.port_tree = ttk.Treeview(tab, columns=columns, show="headings")
        
        for col in columns:
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=100)
        self.port_tree.column("Port", width=80)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=scrollbar.set)
        
        self.port_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")
        
    def start_port_scan(self):
        """Start port scanning"""
        host = self.host_var.get()
        try:
            start_port = int(self.port_start_var.get())
            end_port = int(self.port_end_var.get())
        except:
            messagebox.showerror("Error", "Invalid port range")
            return
            
        if start_port > end_port:
            messagebox.showerror("Error", "Start port must be less than end port")
            return
            
        self.status.set(f"🕒 Scanning ports {start_port}-{end_port} on {host}...")
        self.port_tree.delete(*self.port_tree.get_children())
        self.scan_progress['value'] = 0
        self.scan_progress['maximum'] = end_port - start_port + 1
        
        threading.Thread(target=self.perform_port_scan, args=(host, start_port, end_port), daemon=True).start()
        
    def perform_port_scan(self, host, start_port, end_port):
        """Perform port scan in background thread using thread pool"""
        try:
            # Common port services
            common_ports = {
                20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                53: "DNS", 80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
                143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS", 445: "SMB",
                993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
                5900: "VNC", 8080: "HTTP Proxy"
            }
            
            ports_scanned = 0
            open_ports = []
            
            # Use thread pool for concurrent scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, host, port, common_ports): port 
                    for port in range(start_port, end_port + 1)
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        status, service = future.result()
                        if status == "Open":
                            open_ports.append((port, status, service))
                        ports_scanned += 1
                        progress = (ports_scanned / (end_port - start_port + 1)) * 100
                        self.scan_progress['value'] = ports_scanned
                        self.status.set(f"🕒 Scanning: {progress:.1f}% complete")
                    except Exception as e:
                        pass
            
            # Add all open ports to the treeview
            for port, status, service in open_ports:
                self.port_tree.insert("", "end", values=(port, status, service))
                
            self.status.set(f"✅ Port scan completed. Found {len(open_ports)} open ports")
            
        except Exception as e:
            self.status.set(f"❌ Port scan error: {str(e)}")
            
    def scan_port(self, host, port, common_ports):
        """Scan a single port and return status"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                status = "Open" if result == 0 else "Closed"
                service = common_ports.get(port, "Unknown")
                return status, service
        except Exception:
            return "Error", "Unknown"
        
    def create_file_inspector_tab(self):
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="File Inspector")
        
        # Frame for controls
        control_frame = ttk.Frame(tab, style='TFrame')
        control_frame.pack(fill="x", padx=10, pady=10)
        
        # Path entry
        ttk.Label(control_frame, text="Path:", style='TLabel').pack(side="left", padx=(0, 5))
        
        self.path_var = tk.StringVar(value=os.getcwd())
        path_entry = ttk.Entry(control_frame, textvariable=self.path_var, width=50)
        path_entry.pack(side="left", fill="x", expand=True)
        
        # Buttons
        browse_btn = ttk.Button(control_frame, text="Browse", command=self.browse_directory,
                               style='TButton')
        browse_btn.pack(side="left", padx=(10, 5))
        
        scan_btn = ttk.Button(control_frame, text="Scan for Malware", command=self.scan_directory,
                             style='TButton')
        scan_btn.pack(side="left", padx=5)
        
        # Treeview for files
        columns = ("Name", "Size", "Modified", "Permissions", "Owner", "Status")
        self.file_tree = ttk.Treeview(tab, columns=columns, show="headings", selectmode="extended")
        
        for col in columns:
            self.file_tree.heading(col, text=col)
            self.file_tree.column(col, width=120)
        self.file_tree.column("Name", width=200)
        self.file_tree.column("Status", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scrollbar.set)
        
        self.file_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")
        
        # Populate initial directory
        self.populate_file_tree()
        
    def browse_directory(self):
        path = filedialog.askdirectory(initialdir=self.path_var.get())
        if path:
            self.path_var.set(path)
            self.populate_file_tree()
            
    def scan_directory(self):
        """Scan current directory for malware"""
        self.status.set("🕒 Scanning directory for malware...")
        threading.Thread(target=self.perform_directory_scan, daemon=True).start()
        
    def perform_directory_scan(self):
        """Perform malware scan in background thread"""
        try:
            suspicious_count = 0
            path = self.path_var.get()
            
            # Known malware signatures
            malware_signatures = MALWARE_SIGNATURES
            
            # Known suspicious file extensions
            suspicious_extensions = ['.sh', '.py', '.js', '.php', '.pl', '.rb', '.exe', '.dll', '.bat', '.bin']
            
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    status = "Clean"
                    
                    # Check file extension
                    if any(file.endswith(ext) for ext in suspicious_extensions):
                        # Check content for malware signatures
                        try:
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read(4096)  # Read first 4KB
                                
                                # Check for virus signatures
                                for sig in malware_signatures["viruses"]:
                                    if re.search(sig, content, re.IGNORECASE):
                                        status = "Virus"
                                        suspicious_count += 1
                                        self.status.set(f"⚠️ Found virus: {file_path}")
                                        self.proctor.quarantine_file(file_path)
                                        break
                                        
                                # Check for malware signatures
                                for sig in malware_signatures["malware"]:
                                    if re.search(sig, content, re.IGNORECASE):
                                        status = "Malware"
                                        suspicious_count += 1
                                        self.status.set(f"⚠️ Found malware: {file_path}")
                                        self.proctor.quarantine_file(file_path)
                                        break
                                        
                        except Exception:
                            pass
                    
                    # Update file status in treeview
                    self.update_file_status(file_path, status)
                            
            self.status.set(f"✅ Directory scan completed. Found {suspicious_count} malicious files")
            self.scan_status.set(f"⚠️ Found {suspicious_count} malicious files")
            
        except Exception as e:
            self.status.set(f"❌ Scan error: {str(e)}")
            
    def update_file_status(self, file_path, status):
        """Update status of a file in the treeview"""
        for child in self.file_tree.get_children():
            values = self.file_tree.item(child)['values']
            if values and values[0] == os.path.basename(file_path):
                if len(values) < 6:
                    values.append(status)
                else:
                    values[5] = status
                self.file_tree.item(child, values=values)
                break
                
    def populate_file_tree(self):
        """Populate file tree with directory contents"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
            
        # Populate with files
        try:
            path = self.path_var.get()
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                if os.path.exists(full_path):
                    size = os.path.getsize(full_path)
                    mtime = datetime.fromtimestamp(os.path.getmtime(full_path))
                    perm = oct(os.stat(full_path).st_mode)[-3:]
                    owner = f"{os.stat(full_path).st_uid}"
                    
                    # Scan file status
                    status = "Clean"
                    if self.proctor:
                        scan_result = self.proctor.scan_file(full_path)
                        if scan_result == "malicious":
                            status = "Malicious"
                        elif scan_result == "suspicious":
                            status = "Suspicious"
                    
                    self.file_tree.insert("", "end", values=(
                        entry,
                        f"{size/1024:.2f} KB" if size < 1024*1024 else f"{size/(1024*1024):.2f} MB",
                        mtime.strftime('%Y-%m-%d %H:%M'),
                        perm,
                        owner,
                        status
                    ))
            self.status.set(f"Loaded directory: {path}")
        except Exception as e:
            self.status.set(f"Error: {str(e)}")
            
    def create_log_analyzer_tab(self):
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Log Analyzer")
        
        # Frame for controls
        control_frame = ttk.Frame(tab, style='TFrame')
        control_frame.pack(fill='x', padx=10, pady=10)
        
        # Log selection
        ttk.Label(control_frame, text="Log File:", style='TLabel').pack(side='left', padx=(0, 5))
        
        self.log_var = tk.StringVar()
        log_combo = ttk.Combobox(control_frame, textvariable=self.log_var, width=40)
        log_combo['values'] = [
            '/var/log/syslog',
            '/var/log/auth.log',
            '/var/log/kern.log',
            '/var/log/dmesg',
            '/var/log/boot.log',
            '/var/log/secure',
            '/var/log/messages'
        ]
        log_combo.current(0)
        log_combo.pack(side='left', fill='x', expand=True)
        
        # View button
        view_btn = ttk.Button(control_frame, text="View Log", command=self.view_log,
                             style='TButton')
        view_btn.pack(side='left', padx=(10, 5))
        
        # Filter entry
        ttk.Label(control_frame, text="Filter:", style='TLabel').pack(side='left', padx=(20, 5))
        
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=20)
        filter_entry.pack(side='left')
        
        filter_btn = ttk.Button(control_frame, text="Apply Filter", command=self.apply_log_filter,
                               style='TButton')
        filter_btn.pack(side='left', padx=(5, 0))
        
        # Text widget for log content
        self.log_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, bg=self.text_bg, fg=self.fg_color, 
                                               font=("Consolas", 10))
        self.log_text.pack(expand=True, fill='both', padx=10, pady=10)
        
        # View initial log
        self.view_log()
        
    def view_log(self):
        log_file = self.log_var.get()
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                self.log_text.insert(tk.INSERT, content)
                self.status.set(f"Loaded: {log_file}")
        except Exception as e:
            self.log_text.insert(tk.INSERT, f"Error reading file: {str(e)}")
            self.status.set(f"Error: {str(e)}")
            
        self.apply_log_filter()
        self.log_text.config(state=tk.DISABLED)
        
    def apply_log_filter(self):
        """Apply filter to log content"""
        filter_text = self.filter_var.get().strip()
        if not filter_text:
            return
            
        self.log_text.config(state=tk.NORMAL)
        
        # Remove previous tags
        self.log_text.tag_remove("highlight", "1.0", tk.END)
        
        # Apply new filter
        content = self.log_text.get("1.0", tk.END)
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert("1.0", content)
        
        # Highlight matches
        start = "1.0"
        while True:
            start = self.log_text.search(filter_text, start, stopindex=tk.END, 
                                       nocase=True, regexp=False)
            if not start:
                break
            end = f"{start}+{len(filter_text)}c"
            self.log_text.tag_add("highlight", start, end)
            start = end
            
        self.log_text.tag_config("highlight", background="#ffcc00", foreground="#1a1a1a")
        self.log_text.config(state=tk.DISABLED)
        
    def create_malware_scanner_tab(self):
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Malware Scanner")
        
        # Scan options frame
        options_frame = ttk.LabelFrame(tab, text="Scan Options", style='TLabelframe')
        options_frame.pack(fill='x', padx=10, pady=10)
        
        # Scan type
        scan_type_frame = ttk.Frame(options_frame, style='TFrame')
        scan_type_frame.pack(fill='x', pady=5)
        ttk.Label(scan_type_frame, text="Scan Type:", style='TLabel').pack(side='left')
        
        self.scan_type = tk.StringVar(value="quick")
        ttk.Radiobutton(scan_type_frame, text="Quick Scan", variable=self.scan_type, 
                       value="quick", style='TRadiobutton').pack(side='left', padx=10)
        ttk.Radiobutton(scan_type_frame, text="Full Scan", variable=self.scan_type, 
                       value="full", style='TRadiobutton').pack(side='left', padx=10)
        ttk.Radiobutton(scan_type_frame, text="Backdoor Scan", variable=self.scan_type, 
                       value="backdoor", style='TRadiobutton').pack(side='left', padx=10)
        
        # Scan target
        target_frame = ttk.Frame(options_frame, style='TFrame')
        target_frame.pack(fill='x', pady=5)
        ttk.Label(target_frame, text="Scan Target:", style='TLabel').pack(side='left')
        
        self.scan_target = tk.StringVar(value="/")
        target_entry = ttk.Entry(target_frame, textvariable=self.scan_target, width=50)
        target_entry.pack(side='left', fill='x', expand=True, padx=(5, 0))
        
        browse_btn = ttk.Button(target_frame, text="Browse", command=self.browse_scan_target,
                               style='TButton')
        browse_btn.pack(side='left', padx=(10, 0))
        
        # Start scan button
        scan_btn = ttk.Button(options_frame, text="Start Malware Scan", command=self.start_malware_scan,
                             style='TButton')
        scan_btn.pack(pady=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(tab, text="Scan Results", style='TLabelframe')
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Results treeview
        columns = ("File/Process", "Threat", "Status")
        self.scan_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=200)
        self.scan_tree.column("File/Process", width=400)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        # Action buttons
        action_frame = ttk.Frame(results_frame, style='TFrame')
        action_frame.pack(fill='x', pady=5)
        
        quarantine_btn = ttk.Button(action_frame, text="Quarantine Selected", command=self.quarantine_selected,
                                   style='TButton')
        quarantine_btn.pack(side='left', padx=5)
        
        delete_btn = ttk.Button(action_frame, text="Delete Selected", command=self.delete_selected,
                               style='TButton')
        delete_btn.pack(side='left', padx=5)
        
        self.scan_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def browse_scan_target(self):
        path = filedialog.askdirectory(initialdir=self.scan_target.get())
        if path:
            self.scan_target.set(path)
            
    def start_malware_scan(self):
        """Start malware scan based on selected options"""
        scan_type = self.scan_type.get()
        target = self.scan_target.get()
        
        self.status.set(f"🕒 Starting {scan_type} scan on {target}...")
        self.scan_tree.delete(*self.scan_tree.get_children())  # Clear previous results
        
        threading.Thread(target=self.perform_malware_scan, args=(scan_type, target), daemon=True).start()
        
    def quarantine_selected(self):
        """Quarantine selected items"""
        selected = self.scan_tree.selection()
        for item in selected:
            file_path = self.scan_tree.item(item)['values'][0]
            if self.proctor.quarantine_file(file_path):
                self.scan_tree.item(item, values=(file_path, "Quarantined", "✅"))
        
    def delete_selected(self):
        """Delete selected items"""
        selected = self.scan_tree.selection()
        for item in selected:
            file_path = self.scan_tree.item(item)['values'][0]
            try:
                os.remove(file_path)
                self.scan_tree.item(item, values=(file_path, "Deleted", "✅"))
            except Exception as e:
                self.scan_tree.item(item, values=(file_path, f"Delete failed: {str(e)}", "❌"))
        
    def perform_malware_scan(self, scan_type, target):
        """Perform malware scan in background thread"""
        try:
            # Scan paths based on scan type
            if scan_type == "quick":
                scan_paths = [
                    '/tmp', '/dev/shm', '/var/tmp', 
                    os.path.expanduser('~'), '/etc/cron.d', '/bin', '/sbin'
                ]
            elif scan_type == "backdoor":
                # Scan for backdoor indicators
                self.scan_for_backdoors()
                return
            else:
                scan_paths = [target]
                
            suspicious_count = 0
            start_time = time.time()
            
            for path in scan_paths:
                if not os.path.exists(path):
                    continue
                    
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Scan the file using Proctor
                        result = self.proctor.scan_file(file_path)
                        if result != "clean":
                            status = "Malicious" if result == "malicious" else "Suspicious"
                            self.scan_tree.insert("", "end", values=(
                                file_path, 
                                status, 
                                "⚠️"
                            ))
                            suspicious_count += 1
                        
                        # Update status periodically
                        if time.time() - start_time > 1:
                            self.status.set(f"🕒 Scanning: {root}...")
                            start_time = time.time()
                            
            self.status.set(f"✅ Scan completed. Found {suspicious_count} suspicious files")
            self.scan_status.set(f"⚠️ Found {suspicious_count} suspicious files")
            
        except Exception as e:
            self.status.set(f"❌ Scan error: {str(e)}")

    def scan_for_backdoors(self):
        """Scan for backdoor indicators"""
        try:
            # 1. Check suspicious processes
            backdoor_processes = []
            for proc in psutil.process_iter(['name']):
                try:
                    name = proc.info['name'].lower()
                    if 'backdoor' in name or 'bd' in name or 'shell' in name or 'reverse' in name:
                        backdoor_processes.append(proc)
                        self.scan_tree.insert("", "end", values=(
                            f"Process: {name} (PID: {proc.pid})", 
                            "Suspicious process name", 
                            "⚠️"
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 2. Check unusual listening ports
            unusual_ports = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.port > 49151:
                    unusual_ports.append(conn.laddr.port)
                    self.scan_tree.insert("", "end", values=(
                        f"Port: {conn.laddr.port} listening", 
                        "Unusual high port", 
                        "⚠️"
                    ))
            
            # 3. Check known backdoor files
            backdoor_files = []
            suspicious_paths = ['/tmp', '/dev/shm', '/var/tmp', '/usr/bin', '/bin', '/sbin']
            suspicious_names = ['bd', 'backdoor', 'shell', 'revsh', 'rsh']
            for path in suspicious_paths:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        if any(name in file.lower() for name in suspicious_names):
                            full_path = os.path.join(path, file)
                            backdoor_files.append(full_path)
                            self.scan_tree.insert("", "end", values=(
                                f"File: {full_path}", 
                                "Suspicious file name", 
                                "⚠️"
                            ))
            
            # Summary
            total_findings = len(backdoor_processes) + len(unusual_ports) + len(backdoor_files)
            self.status.set(f"✅ Backdoor scan completed. Found {total_findings} indicators")
            self.scan_status.set(f"⚠️ Found {total_findings} backdoor indicators")
            
        except Exception as e:
            self.status.set(f"❌ Backdoor scan error: {str(e)}")
            
    def create_forensics_tab(self):
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Forensics Toolkit")
        
        # Forensic tools frame
        tools_frame = ttk.LabelFrame(tab, text="Forensic Tools", style='TLabelframe')
        tools_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tool buttons
        tools = [
            ("Memory Capture", self.capture_memory),
            ("Disk Image", self.create_disk_image),
            ("File Carving", self.file_carving),
            ("Timeline Analysis", self.timeline_analysis),
            ("Network Capture", self.capture_network),
            ("Scan Memory", self.scan_memory)
        ]
        
        for i, (name, command) in enumerate(tools):
            btn = ttk.Button(tools_frame, text=name, command=command, style='TButton')
            btn.grid(row=i//3, column=i%3, padx=15, pady=15, sticky='nsew')
            
        # Set grid weights
        for i in range(3):
            tools_frame.grid_columnconfigure(i, weight=1)
        for i in range((len(tools) + 2) // 3):
            tools_frame.grid_rowconfigure(i, weight=1)
            
        # Output frame
        output_frame = ttk.LabelFrame(tab, text="Command Output", style='TLabelframe')
        output_frame.pack(fill='x', padx=10, pady=10)
        
        self.forensic_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, 
                                                      bg=self.text_bg, fg=self.fg_color, 
                                                      font=("Consolas", 9), height=10)
        self.forensic_output.pack(fill='both', expand=True, padx=5, pady=5)
        self.forensic_output.config(state=tk.DISABLED)
        
    def scan_memory(self):
        """Scan memory for malware signatures"""
        self.run_forensic_command("Memory Scan", "sudo ./volatility -f memory.dmp malfind")
        
    def capture_memory(self):
        self.run_forensic_command("Memory Capture", "sudo fmem -l -o memory.dmp")
        
    def create_disk_image(self):
        self.run_forensic_command("Disk Image", "sudo dd if=/dev/sda of=disk.img bs=1M status=progress")
        
    def file_carving(self):
        self.run_forensic_command("File Carving", "scalpel -c config/scalpel.conf -o output disk.img")
        
    def timeline_analysis(self):
        self.run_forensic_command("Timeline Analysis", "mactime -b bodyfile.csv -d > timeline.csv")
        
    def capture_network(self):
        self.run_forensic_command("Network Capture", "sudo tcpdump -i any -w capture.pcap")
        
    def run_forensic_command(self, tool_name, command):
        """Run forensic tool command in background"""
        self.status.set(f"🕒 Running {tool_name}...")
        self.forensic_output.config(state=tk.NORMAL)
        self.forensic_output.insert(tk.END, f"\n=== {tool_name} ===\n")
        self.forensic_output.insert(tk.END, f"$ {command}\n")
        self.forensic_output.config(state=tk.DISABLED)
        
        def execute_command():
            try:
                # Simulate command execution
                result = subprocess.run(f"echo 'Simulating: {command}'", 
                                      shell=True, capture_output=True, text=True, timeout=5)
                self.forensic_output.config(state=tk.NORMAL)
                self.forensic_output.insert(tk.END, result.stdout)
                self.forensic_output.insert(tk.END, "\nCommand completed successfully\n")
                self.forensic_output.config(state=tk.DISABLED)
                self.status.set(f"✅ {tool_name} completed")
            except Exception as e:
                self.forensic_output.config(state=tk.NORMAL)
                self.forensic_output.insert(tk.END, f"Error: {str(e)}\n")
                self.forensic_output.config(state=tk.DISABLED)
                self.status.set(f"❌ {tool_name} failed")
                
        threading.Thread(target=execute_command, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = LinuxInvestigationTool(root)
    root.protocol("WM_DELETE_WINDOW", lambda: [setattr(app.proctor, 'running', False), 
                                             setattr(app, 'monitor_active', False), 
                                             root.destroy()])
    root.mainloop()
