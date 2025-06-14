"""
Log generator for AI Threat Hunter testing.
This module creates realistic network log datasets for testing threat detection.
"""
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

def generate_dns_exfil_logs(count: int = 10, base_time: datetime = None) -> List[Dict[str, Any]]:
    """Generate realistic DNS exfiltration logs"""
    if base_time is None:
        base_time = datetime.now()
        
    logs = []
    source_ip = "192.168.2.45"
    
    for i in range(count):
        # Create pseudo-random exfiltration domains with encoded data
        encoded_data = ''.join(random.choices('abcdef0123456789', k=30))
        domain = f"data-{encoded_data}.attacker-domain.com"
        
        # Create timestamp with small increments
        timestamp = (base_time + timedelta(seconds=i*12)).isoformat()
        
        logs.append({
            "timestamp": timestamp,
            "source_ip": source_ip,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "protocol": "UDP",
            "action": "allowed",
            "dns_query": domain,
            "bytes_out": random.randint(4500, 9000),
            "bytes_in": random.randint(300, 600)
        })
    
    return logs

def generate_port_scan_logs(count: int = 5, base_time: datetime = None) -> List[Dict[str, Any]]:
    """Generate realistic port scanning logs"""
    if base_time is None:
        base_time = datetime.now()
        
    logs = []
    source_ip = "203.0.113.42"  # Example external IP
    target_ip = "192.168.1.10"  # Target internal server
    
    # Common ports to scan
    ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
    
    for i in range(count):
        # Select random ports to scan in this batch
        scan_ports = random.sample(ports, min(3, len(ports)))
        
        for port in scan_ports:
            # Create timestamp with small increments
            timestamp = (base_time + timedelta(seconds=i*5 + ports.index(port))).isoformat()
            
            logs.append({
                "timestamp": timestamp,
                "source_ip": source_ip,
                "dest_ip": target_ip,
                "dest_port": port,
                "protocol": "TCP",
                "action": "blocked" if random.random() > 0.3 else "allowed",
                "bytes_out": random.randint(60, 120),
                "bytes_in": random.randint(40, 100) if random.random() > 0.5 else 0
            })
    
    return logs

def generate_phishing_logs(count: int = 2, base_time: datetime = None) -> List[Dict[str, Any]]:
    """Generate realistic phishing email connection logs"""
    if base_time is None:
        base_time = datetime.now()
        
    logs = []
    victim_ip = "192.168.1.55"  # Victim workstation
    phishing_domains = [
        "secure-banking-portal.com",
        "account-verification-required.net",
        "document-share.info",
        "invoice-payment-secure.com"
    ]
    
    for i in range(count):
        domain = random.choice(phishing_domains)
        
        # Initial connection (HTTP/HTTPS)
        timestamp = (base_time + timedelta(minutes=i*15)).isoformat()
        logs.append({
            "timestamp": timestamp,
            "source_ip": victim_ip,
            "dest_ip": "45.77.65." + str(random.randint(1, 254)),
            "dest_port": 443 if random.random() > 0.3 else 80,
            "protocol": "TCP",
            "action": "allowed",
            "http_host": domain,
            "http_uri": "/login.php",
            "http_method": "GET",
            "bytes_out": random.randint(400, 700),
            "bytes_in": random.randint(15000, 30000)
        })
        
        # Form submission (usually POST)
        timestamp = (base_time + timedelta(minutes=i*15, seconds=45)).isoformat()
        logs.append({
            "timestamp": timestamp,
            "source_ip": victim_ip,
            "dest_ip": "45.77.65." + str(random.randint(1, 254)),
            "dest_port": 443 if random.random() > 0.3 else 80,
            "protocol": "TCP",
            "action": "allowed",
            "http_host": domain,
            "http_uri": "/submit.php",
            "http_method": "POST",
            "http_content_length": random.randint(500, 1500),
            "bytes_out": random.randint(800, 1800),
            "bytes_in": random.randint(2000, 5000)
        })
    
    return logs

def generate_smb_rdp_logs(count: int = 8, base_time: datetime = None) -> List[Dict[str, Any]]:
    """Generate realistic lateral movement logs using SMB/RDP"""
    if base_time is None:
        base_time = datetime.now()
        
    logs = []
    # Starting with a compromised host
    compromised_ip = "192.168.1.55"
    
    # Target systems for lateral movement
    targets = [
        {"ip": "192.168.1.10", "hostname": "FILESERVER01"},
        {"ip": "192.168.1.20", "hostname": "WORKSTATION-HR1"},
        {"ip": "192.168.1.30", "hostname": "WORKSTATION-HR2"},
        {"ip": "192.168.1.40", "hostname": "DOMAINCONTROLLER"}
    ]
    
    for i in range(count):
        # Select a random target
        target = random.choice(targets)
        
        # Determine protocol (SMB or RDP)
        protocol = "TCP"
        port = 445 if random.random() > 0.5 else 3389
        service = "SMB" if port == 445 else "RDP"
        
        # Create timestamp with realistic intervals
        timestamp = (base_time + timedelta(minutes=i*5)).isoformat()
        
        logs.append({
            "timestamp": timestamp,
            "source_ip": compromised_ip,
            "dest_ip": target["ip"],
            "dest_port": port,
            "protocol": protocol,
            "service": service,
            "action": "allowed",
            "user": "administrator" if random.random() > 0.7 else f"user{random.randint(1,10)}",
            "bytes_out": random.randint(1200, 5000),
            "bytes_in": random.randint(5000, 20000)
        })
    
    return logs

def combine_attack_sequence(base_time: datetime = None) -> List[Dict[str, Any]]:
    """Generate a complete multi-stage attack sequence"""
    if base_time is None:
        base_time = datetime.now()
    
    # Stage 1: Reconnaissance
    recon_time = base_time
    recon_logs = generate_port_scan_logs(count=5, base_time=recon_time)
    
    # Stage 2: Initial Access (30 minutes later)
    access_time = base_time + timedelta(minutes=30)
    access_logs = generate_phishing_logs(count=2, base_time=access_time)
    
    # Stage 3: Lateral Movement (2 hours later)
    lateral_time = base_time + timedelta(hours=2)
    lateral_logs = generate_smb_rdp_logs(count=8, base_time=lateral_time)
    
    # Stage 4: Data Exfiltration (3 hours later)
    exfil_time = base_time + timedelta(hours=3)
    exfil_logs = generate_dns_exfil_logs(count=10, base_time=exfil_time)
    
    # Combine all logs
    combined_logs = recon_logs + access_logs + lateral_logs + exfil_logs
    
    # Sort by timestamp
    sorted_logs = sorted(combined_logs, key=lambda x: x["timestamp"])
    
    return sorted_logs
