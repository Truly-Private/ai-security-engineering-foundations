#!/usr/bin/env python
"""
Use Case Demo for AI Threat Hunter.
Demonstrates practical use cases for AI Threat Hunter with external mocks.
"""
import asyncio
import json
from typing import Dict, List, Any
from ai_threat_hunter import AIThreatHunter
from external_mocks import EnhancedMockTransformer
from log_generator import (
    generate_dns_exfil_logs, 
    generate_port_scan_logs,
    generate_smb_rdp_logs,
    generate_phishing_logs,
    combine_attack_sequence
)

def print_separator(title: str = "", width: int = 70):
    """Print a separator line with optional title."""
    if title:
        print(f"\n{'-' * 10} {title} {'-' * (width - 12 - len(title))}")
    else:
        print(f"\n{'-' * width}")

# 1. Create a custom AIThreatHunter using the enhanced mock
class EnhancedAIThreatHunter(AIThreatHunter):
    def __init__(self, model_name: str = "enhanced-sec-model"):
        super().__init__(model_name)
        # Replace the default mock with our enhanced version
        self.security_llm = EnhancedMockTransformer(model_name)
    
    def _parse_ai_response(self, response_text: str, log_summary: str) -> Dict[str, Any]:
        """Enhanced parsing logic for the mock AI responses"""
        print(f"\n[+] Parsing response with enhanced logic")
        
        # Initialize with default values
        parsed_data = {
            "primary_vector": "Undetermined",
            "threats_detected": ["No specific patterns identified by parser"],
            "risk_level": 0.0,
            "recommended_actions": ["Review raw analysis"],
            "narrative_summary": "Could not parse narrative.",
            "raw_analysis": response_text,
            "log_summary_processed": log_summary
        }
        
        def _extract_list_from_string(list_str: str) -> List[str]:
            """Extract list items from string representation"""
            list_str = list_str.strip()
            if list_str.startswith('[') and list_str.endswith(']'):
                list_str = list_str[1:-1]
            
            # Split by comma and clean up each item
            items = []
            for item in list_str.split(','):
                cleaned_item = item.strip().replace('"', '').replace("'", "")
                if cleaned_item:
                    items.append(cleaned_item)
            return items
        
        # Enhanced parsing logic specifically for external mocks
        for line in response_text.splitlines():
            line_strip = line.strip()
            if not line_strip:
                continue
            
            line_lower = line_strip.lower()
            
            # Primary Vector
            if "primary vector:" in line_lower:
                parsed_data["primary_vector"] = line_strip.split(":", 1)[1].strip()
                print(f"  - Found primary vector: {parsed_data['primary_vector']}")
            
            # Detected Patterns/Threats
            elif "detected patterns:" in line_lower:
                patterns_str = line_strip.split(":", 1)[1].strip()
                parsed_data["threats_detected"] = _extract_list_from_string(patterns_str)
                print(f"  - Found threats: {parsed_data['threats_detected']}")
            
            # Risk Score
            elif "risk score:" in line_lower:
                risk_str = line_strip.split(":", 1)[1].strip()
                try:
                    parsed_data["risk_level"] = float(risk_str)
                    print(f"  - Found risk level: {parsed_data['risk_level']}")
                except ValueError:
                    print(f"  - Could not parse risk score: {risk_str}")
            
            # Recommended Actions
            elif "recommended actions:" in line_lower:
                actions_str = line_strip.split(":", 1)[1].strip()
                parsed_data["recommended_actions"] = _extract_list_from_string(actions_str)
                print(f"  - Found actions: {parsed_data['recommended_actions']}")
            
            # Narrative
            elif "narrative:" in line_lower:
                narrative_content = line_strip.split(":", 1)[1].strip()
                if narrative_content:
                    parsed_data["narrative_summary"] = narrative_content
                    print(f"  - Found narrative: {narrative_content[:50]}...")
        
        # Filter out empty values
        parsed_data["threats_detected"] = [item for item in parsed_data["threats_detected"] if item]
        parsed_data["recommended_actions"] = [item for item in parsed_data["recommended_actions"] if item]
        
        # Ensure we have default values if parsing failed
        if not parsed_data["threats_detected"]:
            parsed_data["threats_detected"] = ["No specific patterns identified by parser"]
        if not parsed_data["recommended_actions"]:
            parsed_data["recommended_actions"] = ["Review raw analysis"]
        
        return parsed_data

async def run_dns_exfil_use_case():
    """Run a DNS exfiltration detection use case."""
    print_separator("DNS Exfiltration Use Case", 70)
    
    # Generate test logs
    dns_exfil_logs = generate_dns_exfil_logs(count=15)
    
    print(f"Generated {len(dns_exfil_logs)} DNS exfiltration logs.")
    print("Sample log entry:")
    print(json.dumps(dns_exfil_logs[0], indent=2))
    
    # Initialize the enhanced threat hunter
    threat_hunter = EnhancedAIThreatHunter()
    
    # Analyze the generated logs
    print("\nAnalyzing logs for DNS exfiltration threats...")
    analysis_result = await threat_hunter.analyze_network_logs(dns_exfil_logs)
    
    # Display results
    print("\nAnalysis Results:")
    print(json.dumps(analysis_result, indent=2))
    
    # Verify if the analysis matches expected outcome
    primary_vector_match = "exfil" in analysis_result['primary_vector'].lower() or "data exfiltration" in analysis_result['primary_vector'].lower()
    dns_pattern_match = any("dns" in threat.lower() for threat in analysis_result['threats_detected'])
    
    if primary_vector_match and dns_pattern_match:
        print("\n✓ Use case PASSED - Correctly identified DNS exfiltration")
    else:
        print("\n⨯ Use case FAILED - Did not correctly identify the threat")
    
    return analysis_result

async def run_lateral_movement_use_case():
    """Run a lateral movement detection use case."""
    print_separator("Lateral Movement Use Case", 70)
    
    # Generate test logs
    lateral_logs = generate_smb_rdp_logs(count=12)
    
    print(f"Generated {len(lateral_logs)} lateral movement logs.")
    print("Sample log entry:")
    print(json.dumps(lateral_logs[0], indent=2))
    
    # Initialize the enhanced threat hunter
    threat_hunter = EnhancedAIThreatHunter()
    
    # Analyze the generated logs
    print("\nAnalyzing logs for lateral movement threats...")
    analysis_result = await threat_hunter.analyze_network_logs(lateral_logs)
    
    # Display results
    print("\nAnalysis Results:")
    print(json.dumps(analysis_result, indent=2))
    
    # Verify if the analysis matches expected outcome
    primary_vector_match = "lateral" in analysis_result['primary_vector'].lower()
    smb_rdp_pattern_match = any(pattern in " ".join(analysis_result['threats_detected']).lower() 
                               for pattern in ["smb", "rdp", "lateral", "movement"])
    
    if primary_vector_match and smb_rdp_pattern_match:
        print("\n✓ Use case PASSED - Correctly identified lateral movement")
    else:
        print("\n⨯ Use case FAILED - Did not correctly identify the threat")
        print(f"  Primary vector: {analysis_result['primary_vector']}")
        print(f"  Threats detected: {analysis_result['threats_detected']}")
    
    return analysis_result

async def run_multi_stage_attack_use_case():
    """Run a complete multi-stage attack use case."""
    print_separator("Multi-Stage Attack Use Case", 70)
    
    # Generate a complete attack sequence
    attack_logs = combine_attack_sequence()
    
    print(f"Generated {len(attack_logs)} logs across multiple attack stages.")
    print("First few log entries:")
    for i in range(min(3, len(attack_logs))):
        print(f"\nLog {i+1}:")
        print(json.dumps(attack_logs[i], indent=2))
    
    # Initialize the enhanced threat hunter
    threat_hunter = EnhancedAIThreatHunter()
    
    # Analyze the generated logs
    print("\nAnalyzing logs for multi-stage attack...")
    analysis_result = await threat_hunter.analyze_network_logs(attack_logs)
    
    # Display results
    print("\nAnalysis Results:")
    print(json.dumps(analysis_result, indent=2))
    
    # For multi-stage attacks, we'd typically expect multiple threat patterns
    # to be detected across different vectors
    threat_types_detected = len(analysis_result['threats_detected'])
    has_recommendations = len(analysis_result['recommended_actions']) > 0
    
    print(f"\nDetected {threat_types_detected} threat patterns.")
    print(f"Has recommendations: {'Yes' if has_recommendations else 'No'}")
    
    if threat_types_detected > 0 and has_recommendations:
        print("\n✓ Use case processed - Results generated for multi-stage attack")
    else:
        print("\n⨯ Use case had issues - Limited results for multi-stage attack")
    
    return analysis_result

async def run_all_use_cases():
    """Run all available use cases."""
    try:
        # Run DNS exfiltration use case
        await run_dns_exfil_use_case()
        
        # Run lateral movement use case
        await run_lateral_movement_use_case()
        
        # Run multi-stage attack use case
        await run_multi_stage_attack_use_case()
            
        print_separator("All Use Cases Completed", 70)
        
    except Exception as e:
        print(f"Error running use cases: {str(e)}")
        import traceback
        traceback.print_exc()

# Run the use cases
if __name__ == "__main__":
    print("\nAI Threat Hunter Use Case Demo")
    print("=" * 70)
    print("\nThis demo implements the examples from USE_CASE_PLANNING.md")
    print("It demonstrates how to test AI Threat Hunter with external mocks.\n")
    
    asyncio.run(run_all_use_cases())
