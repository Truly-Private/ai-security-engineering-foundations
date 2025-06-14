# python-ai-threat-hunter/ai_threat_hunter.py

import asyncio
import json
from typing import List, Dict, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime

class MockTransformersPipeline:
    def __init__(self, task: str, model: str, device: int = -1):
        self.task = task
        self.model_name = model
        self.device = device
        print(f"MockTransformersPipeline initialized for task '{self.task}' with model '{self.model_name}' on device {self.device}.")

    def __call__(self, prompt: str, max_length: int, temperature: float, do_sample: bool) -> List[Dict[str, str]]:
        print(f"MockTransformersPipeline received prompt (first 100 chars): {prompt[:100]}...")
        print(f"Params: max_length={max_length}, temperature={temperature}, do_sample={do_sample}")

        response_text = ""
        prompt_lower = prompt.lower()
        if "192.168.1.100" in prompt and "smb" in prompt_lower and "rdp" in prompt_lower:
            response_text = '''
            Threat Analysis:
            - Primary Vector: Lateral Movement and Remote Access
            - Detected Patterns: ["SMB_reconnaissance", "RDP_bruteforce_attempt", "potential_credential_harvesting"]
            - Risk Score: 0.85
            - Confidence: High
            - Affected Systems: Likely Windows Servers or Workstations
            - Recommended Actions: ["isolate_source_ip_192.168.1.100", "reset_credentials_for_suspected_accounts", "review_smb_logs", "monitor_rdp_traffic"]
            - Narrative: The source IP 192.168.1.100 exhibited a coordinated sequence of SMB reconnaissance followed by RDP connection attempts. This pattern is highly indicative of an attacker attempting to move laterally within the network, potentially after an initial compromise. The combination of these activities suggests an attempt to gain remote control over critical systems and harvest credentials.
            '''
        elif "unusual dns query" in prompt_lower:
            response_text = '''
            Threat Analysis:
            - Primary Vector: Command and Control (C2) Communication
            - Detected Patterns: ["dns_tunneling_suspicion", "malware_c2_beacon_attempt"]
            - Risk Score: 0.65
            - Confidence: Medium
            - Recommended Actions: ["block_domain_at_firewall", "scan_endpoint_for_malware", "analyze_dns_logs_for_similar_patterns"]
            - Narrative: An unusual DNS query to a non-standard domain was observed. This could be an indicator of malware attempting to communicate with a command and control server.
            '''
        else:
            response_text = '''
            Threat Analysis:
            - Primary Vector: Undetermined
            - Detected Patterns: ["generic_suspicious_network_activity"]
            - Risk Score: 0.30
            - Confidence: Low
            - Recommended Actions: ["monitor_source_activity_closely", "correlate_with_other_security_event_logs"]
            - Narrative: Generic network activity observed. Insufficient data for high-confidence threat assessment at this time. Further correlation required.
            '''
        return [{"generated_text": response_text}]

@dataclass
class ThreatPattern:
    pattern_id: str
    description: str
    attack_vector: str
    indicators: List[str]
    mitigation_strategies: List[str]
    confidence_score: float
    last_seen: datetime = field(default_factory=datetime.now)
    detection_count: int = 1

    def __str__(self):
        return f"Pattern ID: {self.pattern_id} (Vector: {self.attack_vector}, Confidence: {self.confidence_score*100:.2f}%, Count: {self.detection_count})"

class AIThreatHunter:
    def __init__(self, model_name: str = "mock/foundation-sec-8b-mock"):
        print(f"Initializing AIThreatHunter with model: {model_name}")
        self.security_llm = MockTransformersPipeline(
            task="text-generation",
            model=model_name,
            device=-1
        )
        self.known_patterns: List[ThreatPattern] = []
        print("AIThreatHunter initialized. Known patterns: 0")

    async def analyze_network_logs(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not log_entries:
            print("No log entries to analyze.")
            return {
                "primary_vector": "N/A",
                "threats_detected": [],
                "risk_level": 0.0,
                "recommended_actions": [],
                "narrative_summary": "No logs provided for analysis.",
                "raw_analysis": "",
                "log_summary_processed": "N/A"
            }

        print(f"Analyzing {len(log_entries)} network log entries...")
        log_summary = self._prepare_log_context(log_entries)

        analysis_prompt = f'''
As an expert cybersecurity threat hunter, analyze these summarized network logs for sophisticated and subtle threat patterns:

Log Summary:
{log_summary}

Consider the following:
1. Correlated activity across multiple log entries that might indicate a multi-stage attack.
2. Unusual connection sequences, port usage, or data transfer patterns (e.g., large uploads to unknown IPs).
3. Indicators of reconnaissance (e.g., port scanning), lateral movement (e.g., SMB probes followed by RDP attempts), data exfiltration (e.g., large outbound transfers on non-standard ports), or command and control (C2) communication (e.g., beacons to known malicious domains).
4. Deviations from normal baseline behavior (if known, though not provided in this summary).

Based on your analysis, provide:
- A primary threat vector (e.g., "Lateral Movement", "Data Exfiltration Attempt", "C2 Communication", "Reconnaissance"). Use the heading "Primary Vector:".
- A list of detected threat patterns or specific suspicious activities (e.g., ["SMB_reconnaissance", "RDP_bruteforce_attempt", "DNS_tunneling_suspicion"]). Ensure this is a list of strings. Use the heading "Detected Patterns:".
- An overall risk score (a float between 0.0 and 1.0, where 1.0 is highest risk). Use the heading "Risk Score:".
- A list of specific, actionable recommended mitigation or investigation steps. Ensure this is a list of strings. Use the heading "Recommended Actions:".
- A concise narrative summary of the detected threat and its potential implications. Use the heading "Narrative:".

Format your response clearly, with distinct sections for each item above, using the exact headings specified.
Example of expected thought process: "The sequence of SMB probes on multiple hosts followed by an RDP attempt from IP X to Server Y suggests a lateral movement attempt. This is often seen after initial compromise..."
'''

        print("Sending prompt to mock LLM for threat analysis...")
        response = self.security_llm(
            analysis_prompt,
            max_length=700,
            temperature=0.1,
            do_sample=True
        )

        raw_ai_response = response[0]['generated_text']
        print("Received raw analysis from mock LLM.")

        threat_analysis = self._parse_ai_response(raw_ai_response, log_summary)
        await self._update_threat_patterns(threat_analysis, log_entries)

        print("Log analysis complete.")
        return threat_analysis

    def _prepare_log_context(self, logs: List[Dict[str, Any]]) -> str:
        print(f"Preparing context for {len(logs)} log entries...")
        ip_activity: Dict[str, Dict[str, Any]] = {}

        for log in logs:
            source_ip = log.get('source_ip', 'Unknown_IP')
            dest_ip = log.get('dest_ip', 'Unknown_Dest_IP')
            dest_port = str(log.get('dest_port', 'N/A')) # Ensure port is string
            protocol = log.get('protocol', 'TCP')
            timestamp_str = log.get('timestamp', datetime.now().isoformat())
            action = log.get('action', 'allowed')

            key = source_ip
            if key not in ip_activity:
                ip_activity[key] = {
                    "source_ip": source_ip,
                    "connections": 0,
                    "dest_details": set(),
                    "timestamps": [],
                    "actions": set()
                }

            ip_activity[key]["connections"] += 1
            ip_activity[key]["dest_details"].add((dest_ip, dest_port, protocol.upper()))
            ip_activity[key]["timestamps"].append(timestamp_str)
            ip_activity[key]["actions"].add(action)

        context_parts = []
        for ip, data in ip_activity.items():
            sorted_dest_details = sorted(list(data['dest_details']))
            port_protocol_summary = [f"{dp}:{proto} to {dip}" for dip, dp, proto in sorted_dest_details]

            sorted_timestamps = sorted(data['timestamps'])
            time_range = "N/A"
            if sorted_timestamps:
                time_range = f"from {sorted_timestamps[0]} to {sorted_timestamps[-1]}"

            activity_summary = (
                f"IP {data['source_ip']}: {data['connections']} connection(s). "
                f"Destinations/Ports/Protocols: {port_protocol_summary}. "
                f"Actions: {sorted(list(data['actions']))}. "
                f"Activity time range: {time_range}."
            )
            context_parts.append(activity_summary)

        full_summary = " | ".join(context_parts)
        if not full_summary:
            return "No parsable activity found in logs."
        print(f"Prepared log summary (first 300 chars): {full_summary[:300]}...")
        return full_summary

    def _parse_ai_response(self, response_text: str, log_summary: str) -> Dict[str, Any]:
        print("Parsing AI response...")
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
            list_str = list_str.strip()
            if list_str.startswith('[') and list_str.endswith(']'):
                list_str = list_str[1:-1]
            return [item.strip().replace('"', '').replace("'", "") for item in list_str.split(',') if item.strip()]

        # Use more robust parsing by iterating lines and looking for specific headings
        current_section = None
        for line in response_text.splitlines():
            line_strip = line.strip()
            if not line_strip: # Skip empty lines
                continue

            line_lower = line_strip.lower()

            if line_lower.startswith("primary vector:"):
                parsed_data["primary_vector"] = line_strip.split(":", 1)[1].strip()
                current_section = "primary_vector"
            elif line_lower.startswith("detected patterns:"):
                patterns_str = line_strip.split(":", 1)[1].strip()
                parsed_data["threats_detected"] = _extract_list_from_string(patterns_str)
                current_section = "detected_patterns"
            elif line_lower.startswith("risk score:"):
                risk_str = line_strip.split(":", 1)[1].strip()
                try:
                    parsed_data["risk_level"] = float(risk_str)
                except ValueError:
                    print(f"Warning: Could not parse risk score '{risk_str}' to float.")
                current_section = "risk_score"
            elif line_lower.startswith("recommended actions:"):
                actions_str = line_strip.split(":", 1)[1].strip()
                # Check if it's a list on one line or starts a multi-line list
                if actions_str.startswith("[") and actions_str.endswith("]"):
                     parsed_data["recommended_actions"] = _extract_list_from_string(actions_str)
                else: # Multi-line or single item not in brackets
                    parsed_data["recommended_actions"] = [actions_str.replace("- ","").strip()] if actions_str else []
                current_section = "recommended_actions"
            elif line_lower.startswith("narrative:"):
                parsed_data["narrative_summary"] = line_strip.split(":", 1)[1].strip()
                current_section = "narrative"
            elif current_section == "recommended_actions" and (line_strip.startswith("- ") or line_strip.startswith("* ")):
                # Append to multi-line actions if current_section is actions
                action_item = line_strip.lstrip("-* ").strip()
                if parsed_data["recommended_actions"] == ["Review raw analysis"] or not parsed_data["recommended_actions"]: # Initialize if it's default or empty
                    parsed_data["recommended_actions"] = [action_item]
                else:
                    # Avoid adding the initial parsed item again if it was from the heading line
                    if not parsed_data["recommended_actions"][-1].endswith(action_item) and action_item :
                       parsed_data["recommended_actions"].append(action_item)
            elif current_section == "narrative" and not (line_lower.startswith("- ") or ":" in line_lower):
                # Append to multi-line narrative
                if parsed_data["narrative_summary"] == "Could not parse narrative.": # Initialize
                     parsed_data["narrative_summary"] = line_strip
                else:
                     parsed_data["narrative_summary"] += " " + line_strip

        # Cleanup default values if something was parsed
        if parsed_data["threats_detected"] == [""] or not parsed_data["threats_detected"]:
             parsed_data["threats_detected"] = ["No specific patterns identified by parser"]
        if parsed_data["recommended_actions"] == [""] or not parsed_data["recommended_actions"]:
            parsed_data["recommended_actions"] = ["Review raw analysis"]
        # Filter out any empty strings from lists that might have been added
        parsed_data["threats_detected"] = [item for item in parsed_data["threats_detected"] if item]
        parsed_data["recommended_actions"] = [item for item in parsed_data["recommended_actions"] if item]


        print(f"Parsed AI response. Risk level: {parsed_data['risk_level']}, Threats: {parsed_data['threats_detected']}")
        return parsed_data

    async def _update_threat_patterns(self, analysis: Dict[str, Any], log_entries: List[Dict[str, Any]]):
        print(f"Considering update to threat patterns based on analysis (Risk: {analysis.get('risk_level', 0.0)})...")
        LEARNING_THRESHOLD = 0.7

        valid_threats = isinstance(analysis.get('threats_detected'), list) and \
                        analysis['threats_detected'] and \
                        analysis['threats_detected'] != ["No specific patterns identified by parser"] and \
                        any(t for t in analysis['threats_detected']) # Checks if list contains at least one non-empty string

        if analysis.get('risk_level', 0.0) >= LEARNING_THRESHOLD and valid_threats:
            primary_vector = analysis.get('primary_vector', 'Unknown Vector')
            first_valid_threat = next((t for t in analysis['threats_detected'] if t), "unknown_threat")

            new_pattern_signature = f"{primary_vector}_{first_valid_threat}"
            description = analysis.get('narrative_summary', 'No narrative available.')

            existing_pattern = None
            for p in self.known_patterns:
                # Construct signature for existing pattern
                # Prefer threat_type indicator, fallback to first indicator, then pattern description's first part
                pat_first_threat = "unknown_threat"
                if p.indicators:
                    first_threat_indicator = next((ind.split("threat_type:")[-1] for ind in p.indicators if ind.startswith("threat_type:") and ind.split("threat_type:")[-1]), None)
                    if first_threat_indicator:
                        pat_first_threat = first_threat_indicator
                    else: # Fallback to first indicator overall if no threat_type
                        pat_first_threat = p.indicators[0]

                current_pattern_signature = f"{p.attack_vector}_{pat_first_threat}"
                if current_pattern_signature == new_pattern_signature:
                    existing_pattern = p
                    break

            if existing_pattern:
                existing_pattern.confidence_score = (existing_pattern.confidence_score * existing_pattern.detection_count + analysis['risk_level']) / (existing_pattern.detection_count + 1)
                existing_pattern.detection_count += 1
                existing_pattern.last_seen = datetime.now()
                # Potentially update indicators and mitigation strategies by merging
                # existing_pattern.indicators = sorted(list(set(existing_pattern.indicators + self._extract_indicators(log_entries, analysis.get('threats_detected', [])))))
                # existing_pattern.mitigation_strategies = sorted(list(set(existing_pattern.mitigation_strategies + analysis.get('recommended_actions', []))))
                print(f"Updated existing threat pattern: {existing_pattern}")
            else:
                pattern_id = f"pattern_{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{len(self.known_patterns) + 1}"
                indicators = self._extract_indicators(log_entries, analysis.get('threats_detected', []))

                new_pattern = ThreatPattern(
                    pattern_id=pattern_id,
                    description=f"{primary_vector}: {description[:150]}...",
                    attack_vector=primary_vector,
                    indicators=indicators,
                    mitigation_strategies=analysis.get('recommended_actions', []),
                    confidence_score=analysis.get('risk_level', LEARNING_THRESHOLD)
                )
                self.known_patterns.append(new_pattern)
                await self._persist_pattern(new_pattern)
                print(f"New threat pattern learned and persisted: {new_pattern}")
        else:
            print(f"Analysis did not meet threshold for learning (Risk: {analysis.get('risk_level', 0.0)} < {LEARNING_THRESHOLD}), or no valid/specific threats detected.")

        print(f"Total learned patterns: {len(self.known_patterns)}")

    def _extract_indicators(self, logs: List[Dict[str, Any]], detected_threats: List[str]) -> List[str]:
        indicators: Set[str] = set()

        for threat in detected_threats:
            if isinstance(threat, str) and threat:
                indicators.add(f"threat_type:{threat.replace(' ','_')}") # Sanitize threat string for use as indicator

        for log in logs:
            if log.get('source_ip'):
                indicators.add(f"source_ip:{log['source_ip']}")
            if log.get('dest_ip'):
                indicators.add(f"dest_ip:{log['dest_ip']}")
            if log.get('dest_port'):
                indicators.add(f"dest_port:{log['dest_port']}")
            if log.get('protocol'):
                indicators.add(f"protocol:{log['protocol'].upper()}")

        return sorted(list(indicators))

    async def _persist_pattern(self, pattern: ThreatPattern):
        await asyncio.sleep(0.01)
        print(f"Simulated persistence of pattern: {pattern.pattern_id} to knowledge base. Details: {asdict(pattern)}")

    def get_learned_patterns(self) -> List[ThreatPattern]:
        return self.known_patterns

# End of ai_threat_hunter.py
