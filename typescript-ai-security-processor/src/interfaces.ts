// typescript-ai-security-processor/src/interfaces.ts

/**
 * @interface SecurityAlert
 * @description Defines the structure for a basic security alert.
 */
export interface SecurityAlert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  description: string;
  sourceIP: string;
  targetAssets: string[];
  timestamp: Date;
}

/**
 * @interface AIEnhancedAlert
 * @description Extends SecurityAlert with AI-generated insights and context.
 */
export interface AIEnhancedAlert extends SecurityAlert {
  threatIntelligence: string;
  riskAssessment: string;
  recommendedActions: string[];
  confidenceScore: number; // Percentage (0-100)
}
