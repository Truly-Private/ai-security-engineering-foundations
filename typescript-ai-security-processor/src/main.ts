// typescript-ai-security-processor/src/main.ts

import { AISecurityProcessor } from "./AISecurityProcessor";
import { ThreatIntelligenceDB } from "./ThreatIntelligenceDB";
import { SecurityAlert, AIEnhancedAlert } from "./interfaces";

/**
 * @function main
 * @description Main function to demonstrate the AI Security Processor.
 */
async function main() {
  console.log("Initializing AI Security Alert Processor demonstration...");

  // Initialize Threat Intelligence DB
  const threatDB = new ThreatIntelligenceDB();
  // Add a new piece of threat intel for demonstration
  threatDB.addThreatInfo("172.16.0.10", "This IP has been observed scanning internal services.");

  // Initialize AI Security Processor with a mock LLM endpoint URL
  const aiProcessor = new AISecurityProcessor("https://api.mock-llm.com/v1/chat", threatDB);

  // Create a sample security alert
  const sampleAlert: SecurityAlert = {
    id: "alert-001",
    severity: "high",
    type: "Suspicious SMB Activity",
    description: "Multiple SMB connection attempts detected to high-value server 'FS01'.",
    sourceIP: "192.168.1.100", // This IP has specific mock intel
    targetAssets: ["FS01", "DC02"],
    timestamp: new Date(),
  };

  console.log("
Processing a single Security Alert:");
  console.log("Original Alert:");
  console.log(`  - ID: ${sampleAlert.id}`);
  console.log(`  - Severity: ${sampleAlert.severity}`);
  console.log(`  - Source: ${sampleAlert.sourceIP}`);
  console.log(`  - Description: ${sampleAlert.description}`);
  console.log(`  - Target Assets: ${sampleAlert.targetAssets.join(', ')}`);

  try {
    const enhancedAlert = await aiProcessor.enhanceAlert(sampleAlert);
    console.log("
AI-Enhanced Analysis:");
    console.log(`  - Risk Assessment: "${enhancedAlert.riskAssessment}"`);
    console.log(`  - Recommended Actions: ["${enhancedAlert.recommendedActions.join('", "')}"]`);
    console.log(`  - Confidence Score: ${enhancedAlert.confidenceScore}%`);
    console.log(`  - Threat Intelligence for ${enhancedAlert.sourceIP}: "${enhancedAlert.threatIntelligence}"`);
  } catch (error) {
    console.error("Error enhancing alert:", error);
  }

  // Demonstrate alert prioritization
  console.log("

Demonstrating Alert Prioritization with multiple alerts:");
  const alertsToPrioritize: SecurityAlert[] = [
    sampleAlert, // Re-use the high severity alert
    {
      id: "alert-002",
      severity: "medium",
      type: "Unusual DNS Query",
      description: "DNS query to known malicious domain 'malware-domain.com' from workstation 'WKSTN-078'.",
      sourceIP: "10.0.0.53", // This IP also has specific mock intel
      targetAssets: ["WKSTN-078"],
      timestamp: new Date(Date.now() - 60000 * 5), // 5 minutes ago
    },
    {
      id: "alert-003",
      severity: "low",
      type: "Login Anomaly",
      description: "User 'jdoe' logged in outside of normal business hours.",
      sourceIP: "203.0.113.45", // Generic IP for this one
      targetAssets: ["AuthServer"],
      timestamp: new Date(Date.now() - 60000 * 60), // 1 hour ago
    },
     {
      id: "alert-004",
      severity: "critical",
      type: "Ransomware Behavior Detected",
      description: "File encryption activity detected on multiple endpoints.",
      sourceIP: "172.16.0.10", // IP with added intel
      targetAssets: ["Endpoint1", "Endpoint2", "FileShareX"],
      timestamp: new Date(Date.now() - 60000 * 2), // 2 minutes ago
    },
  ];

  console.log(`
Original order of alerts (by ID): ${alertsToPrioritize.map(a => a.id).join(', ')}`);

  try {
    const prioritizedAlerts = await aiProcessor.prioritizeAlerts(alertsToPrioritize);
    console.log("
Prioritized Alerts (Highest to Lowest Priority):");
    prioritizedAlerts.forEach((alert, index) => {
      console.log(
        `  ${index + 1}. ID: ${alert.id} (${alert.type})` +
        ` - Original Severity: ${alert.severity}` +
        ` - AI Confidence: ${alert.confidenceScore}%` +
        ` - AI Risk: "${alert.riskAssessment.substring(0, 50)}..."` // Show a snippet of risk assessment
      );
    });
  } catch (error) {
    console.error("Error prioritizing alerts:", error);
  }

  console.log("

Demonstration complete.");
}

// Run the main function
main().catch(error => {
  console.error("Unhandled error in main function:", error);
});
