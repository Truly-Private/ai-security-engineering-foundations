"""
External mocks for AI Threat Hunter testing.
This module provides enhanced mock implementations for testing AI Threat Hunter.
"""
from typing import List, Dict, Any

class EnhancedMockTransformer:
    """Extended mock transformer with additional threat patterns"""
    
    def __init__(self, model_name: str = "enhanced-sec-model"):
        self.model_name = model_name
        print(f"[+] Initialized Enhanced Mock Transformer: {model_name}")
        
    def __call__(self, prompt: str, **kwargs) -> List[Dict[str, str]]:
        """Process the prompt and return appropriate mock responses"""
        return self.generate(prompt, **kwargs)
            
    def generate(self, prompt: str, **kwargs) -> List[Dict[str, str]]:
        """Generate a mock response based on the prompt content"""
        # Analyze the prompt content to determine which response pattern is most appropriate
        prompt_lower = prompt.lower()
        
        print(f"[DEBUG] Mock analyzing prompt (first 200 chars): {prompt_lower[:200]}...")
        
        # Lateral movement indicators (check first - more specific)
        lateral_ports = ["445:tcp", "3389:tcp", "smb", "rdp"]
        lateral_keywords = ["lateral", "multiple systems"]
        lateral_port_match = any(term in prompt_lower for term in lateral_ports)
        lateral_keyword_match = any(term in prompt_lower for term in lateral_keywords)
        multiple_ips = "192.168.1." in prompt_lower and len(prompt_lower.split("192.168.1.")) > 2
        
        # DNS exfiltration indicators (more specific - must have DNS port AND exfil indicators)
        dns_port_match = "53:udp" in prompt_lower or "8.8.8.8" in prompt_lower
        dns_exfil_indicators = ["exfil", "tunnel", "large dns", "domain", "dns_query"]
        dns_match = dns_port_match and any(term in prompt_lower for term in dns_exfil_indicators)
        
        print(f"[DEBUG] Pattern matching:")
        print(f"  Lateral port match: {lateral_port_match}")
        print(f"  Lateral keyword match: {lateral_keyword_match}")
        print(f"  Multiple IPs: {multiple_ips}")
        print(f"  DNS port match: {dns_port_match}")
        print(f"  DNS exfil indicators: {any(term in prompt_lower for term in dns_exfil_indicators)}")
        print(f"  DNS match: {dns_match}")
        
        # Check lateral movement first (more specific pattern)
        if lateral_port_match and multiple_ips:
            print("[+] Mock detected lateral movement pattern in logs")
            return [{"generated_text": self._generate_lateral_movement_response()}]
        
        # DNS exfiltration indicators
        elif dns_match:
            print("[+] Mock detected DNS exfiltration pattern in logs")
            return [{"generated_text": self._generate_dns_exfil_response()}]
        
        # SSH brute force indicators
        elif any(term in prompt_lower for term in ["ssh", "22:tcp"]) and \
             any(term in prompt_lower for term in ["failed", "attempts", "auth", "login"]):
            print("[+] Mock detected SSH brute force pattern in logs")
            return [{"generated_text": self._generate_ssh_brute_force_response()}]
        
        # Default response for unknown patterns
        else:
            print("[+] Mock defaulting to generic response - no specific threat pattern matched")            return [{"generated_text": self._generate_generic_response()}]
            
    def _generate_dns_exfil_response(self) -> str:
        """Generate DNS exfiltration threat analysis"""
        return '''
        Threat Analysis:
        - Primary Vector: Data Exfiltration
        - Detected Patterns: ["dns_tunneling", "data_exfiltration", "unusually_large_dns_queries"]
        - Risk Score: 0.82
        - Confidence: High
        - Recommended Actions: ["block_suspicious_dns_domains", "isolate_source_ip", "forensic_analysis_of_endpoint"]
        - Narrative: The endpoint 192.168.2.45 is exhibiting suspicious DNS traffic with unusual payload sizes and high entropy domain names. This pattern is consistent with DNS tunneling techniques used for data exfiltration. The long subdomains likely contain encoded data being covertly transmitted to the attacker's infrastructure.
        '''
    
    def _generate_ssh_brute_force_response(self) -> str:
        """Generate SSH brute force threat analysis"""
        return '''
        Threat Analysis:
        - Primary Vector: Initial Access
        - Detected Patterns: ["ssh_brute_force", "credential_stuffing", "authentication_failure"]
        - Risk Score: 0.75
        - Confidence: Medium
        - Recommended Actions: ["implement_account_lockout", "enable_2fa", "block_source_ips", "review_ssh_logs"]
        - Narrative: Multiple failed SSH authentication attempts were observed from various source IPs targeting the same user accounts. This is indicative of a coordinated brute force attack attempting to gain unauthorized access to the system. The pattern suggests credential stuffing with commonly used passwords.
        '''
        
    def _generate_lateral_movement_response(self) -> str:
        """Generate lateral movement threat analysis"""
        return '''
        Threat Analysis:
        - Primary Vector: Lateral Movement
        - Detected Patterns: ["smb_reconnaissance", "credential_access", "admin_share_abuse"]
        - Risk Score: 0.85
        - Confidence: High
        - Affected Systems: Windows Servers and Workstations
        - Recommended Actions: ["isolate_compromised_hosts", "reset_credentials", "monitor_admin_share_access"]
        - Narrative: The traffic patterns show evidence of lateral movement through the network using SMB protocol and administrative shares. An attacker appears to be using compromised credentials to access multiple systems, potentially to gather additional credentials or deploy remote access tools.
        '''
    
    def _generate_generic_response(self) -> str:
        """Generate generic threat analysis for unknown patterns"""
        return '''
        Threat Analysis:
        - Primary Vector: Undetermined
        - Detected Patterns: ["anomalous_traffic", "potential_suspicious_activity"]
        - Risk Score: 0.45
        - Confidence: Low
        - Recommended Actions: ["continue_monitoring", "collect_additional_data"]
        - Narrative: Some anomalous traffic patterns were observed that deviate from the baseline, but there is insufficient evidence to categorize this as a specific threat. Additional monitoring and data collection is recommended to determine if this represents malicious activity.
        '''
