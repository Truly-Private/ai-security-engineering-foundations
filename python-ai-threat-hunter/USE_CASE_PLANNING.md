# Planning AI Threat Hunter Use Cases with External Mocks

This guide provides a structured approach to planning and implementing use cases for the AI Threat Hunter tool using external mocks. By following these steps, you can create realistic security scenarios while ensuring the core AI Threat Hunter functions work effectively.

## Table of Contents

1. [Understanding the Current Architecture](#understanding-the-current-architecture)
2. [Planning a Use Case](#planning-a-use-case)
3. [Creating External Mocks](#creating-external-mocks)
4. [Implementing a Sample Use Case](#implementing-a-sample-use-case)
5. [Testing and Validation](#testing-and-validation)
6. [Advanced Scenarios](#advanced-scenarios)

## Understanding the Current Architecture

The AI Threat Hunter currently uses a `MockTransformersPipeline` class that simulates an AI model's behavior. This mock:

- Accepts prompts regarding network log analysis
- Returns pre-defined threat analysis based on pattern matching
- Simulates different types of threats (lateral movement, DNS tunneling, etc.)

Key functions in the AI Threat Hunter that we want to preserve:

1. `analyze_network_logs()`: Core analysis function
2. `_parse_ai_response()`: Handles the response structure
3. `_update_threat_patterns()`: Maintains and updates the threat knowledge base
4. `_prepare_log_context()`: Processes log entries into analyzable format

## Planning a Use Case

When planning a use case for AI Threat Hunter, follow these steps:

### 1. Define the Threat Scenario

Start by choosing a realistic cybersecurity scenario:

- **Example 1**: Data exfiltration attempt via DNS tunneling
- **Example 2**: Lateral movement across a network following initial compromise
- **Example 3**: Command and control (C2) beaconing from an infected endpoint

### 2. Create the Dataset

Design network logs that realistically represent the threat:

```python
dns_tunneling_logs = [
    {
        "timestamp": "2023-07-12T14:22:35",
        "source_ip": "192.168.2.45",
        "dest_ip": "8.8.8.8",  # Public DNS server
        "dest_port": 53,       # DNS port
        "protocol": "UDP",
        "action": "allowed",
        "dns_query": "data-exfil-aabbccddeeff11223344.attacker-domain.com",
        "bytes_out": 8544,     # Suspiciously large for DNS
        "bytes_in": 512
    },
    # Additional related log entries...
]
```

### 3. Define Expected Outcomes

Document the expected results of the analysis:

- **Primary Vector**: "Data Exfiltration"
- **Risk Score**: 0.75-0.85
- **Detected Patterns**: ["dns_tunneling", "data_exfiltration"]
- **Recommended Actions**: Block the domain, isolate the host, etc.

## Creating External Mocks

To support your use case, you'll need to:

### 1. Extend the Mock AI System

```python
# Create a new module called external_mocks.py
from typing import List, Dict, Any

class EnhancedMockTransformer:
    """Extended mock transformer with additional threat patterns"""
    
    def __init__(self, model_name: str = "enhanced-sec-model"):
        self.model_name = model_name
        print(f"[+] Initialized Enhanced Mock Transformer: {model_name}")
        
    def __call__(self, prompt: str, **kwargs) -> List[Dict[str, str]]:
        """Process the prompt and return appropriate mock responses"""
        if "dns" in prompt.lower() and "data-exfil" in prompt.lower():
            return [{"generated_text": self._generate_dns_exfil_response()}]
        elif "port 22" in prompt.lower() and "ssh" in prompt.lower():
            return [{"generated_text": self._generate_ssh_brute_force_response()}]
        # Add more pattern matches as needed
        else:
            return [{"generated_text": self._generate_generic_response()}]
            
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
    
    # Add other response generators as needed
```

### 2. Create a Log Generator for Testing

```python
# In a file called log_generator.py
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
```

## Implementing a Sample Use Case

With your mocks in place, now implement your use case:

```python
# In use_case_demo.py
import asyncio
import json
from ai_threat_hunter import AIThreatHunter
from external_mocks import EnhancedMockTransformer
from log_generator import generate_dns_exfil_logs

# 1. Create a custom AIThreatHunter using the enhanced mock
class EnhancedAIThreatHunter(AIThreatHunter):
    def __init__(self, model_name: str = "enhanced-sec-model"):
        super().__init__(model_name)
        # Replace the default mock with our enhanced version
        self.security_llm = EnhancedMockTransformer(model_name)
        
# 2. Generate test logs
dns_exfil_logs = generate_dns_exfil_logs(count=15)

# 3. Run the analysis with our use case
async def run_dns_exfil_use_case():
    print("===== DNS Exfiltration Use Case =====")
    
    # Initialize the enhanced threat hunter
    threat_hunter = EnhancedAIThreatHunter()
    
    # Analyze the generated logs
    analysis_result = await threat_hunter.analyze_network_logs(dns_exfil_logs)
    
    # Display results
    print("\nAnalysis Results:")
    print(json.dumps(analysis_result, indent=2))
    
    # Verify if the analysis matches expected outcome
    if (analysis_result['primary_vector'] == "Data Exfiltration" and 
        any("dns_tunneling" in threat for threat in analysis_result['threats_detected'])):
        print("\n✓ Use case PASSED - Correctly identified DNS exfiltration")
    else:
        print("\n⨯ Use case FAILED - Did not correctly identify the threat")
    
    return analysis_result

# Run the use case
if __name__ == "__main__":
    asyncio.run(run_dns_exfil_use_case())
```

## Testing and Validation

To verify your use case works correctly:

1. **Unit Testing**: Create tests for each component
   ```bash
   pytest test_use_case.py -v
   ```

2. **Validation Checklist**:
   - Does the external mock return expected responses?
   - Are logs processed correctly?
   - Does the AI Threat Hunter correctly identify the threat?
   - Are threat patterns being learned and stored?
   - Does the system provide appropriate mitigation recommendations?

3. **Edge Cases**:
   - Test with mixed threat patterns
   - Test with incomplete or noisy data
   - Test with unusual time ranges or volumes

## Advanced Scenarios

Once you have basic use cases working, you can create more complex scenarios:

### Multi-Stage Attack Simulation

Combine multiple threat types into a complete attack chain:

1. Reconnaissance (port scanning)
2. Initial Access (phishing or exploitation)
3. Lateral Movement (SMB/RDP activity)
4. Exfiltration (DNS tunneling)

```python
# Generate multi-stage attack logs
recon_logs = generate_port_scan_logs(count=5)
access_logs = generate_phishing_logs(count=2)
lateral_logs = generate_smb_rdp_logs(count=8)
exfil_logs = generate_dns_exfil_logs(count=10)

# Combine all logs with appropriate timestamps
combined_logs = recon_logs + access_logs + lateral_logs + exfil_logs
sorted_logs = sorted(combined_logs, key=lambda x: x["timestamp"])

# Run analysis on the combined scenario
analysis_result = await threat_hunter.analyze_network_logs(sorted_logs)
```

### Continuous Learning Testing

Test how the system learns and adapts over time:

```python
# Run multiple analyses with similar patterns
for i in range(5):
    new_logs = generate_variation_of_threat(threat_type="dns_exfil", variation=i)
    result = await threat_hunter.analyze_network_logs(new_logs)
    
    # Check if confidence/detection improves
    print(f"Run {i+1} - Confidence: {result.get('confidence', 0)}")
```

## Conclusion

By using external mocks to simulate AI behavior, you can create realistic security use cases while ensuring the core functions of the AI Threat Hunter work as expected. This allows for:

1. Testing threat detection capabilities without needing real AI models
2. Creating deterministic test scenarios for validation
3. Simulating various attack types and security incidents
4. Developing the threat hunter's capabilities incrementally

Remember to keep the core processing logic intact while replacing only the AI inference component with your mocks. This ensures that when you eventually replace the mocks with real AI models, the rest of the system will continue to function correctly.
