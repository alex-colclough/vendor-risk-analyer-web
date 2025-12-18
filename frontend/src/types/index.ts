export interface UploadedFile {
  id: string;
  original_name: string;
  size_bytes: number;
  mime_type: string;
  uploaded_at: string;
}

export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  title: string;
  description: string;
  recommendation: string;
  affected_controls?: string[];
}

export interface FrameworkCoverage {
  framework: string;
  coverage_percentage: number;
  implemented_controls: number;
  partial_controls: number;
  missing_controls: number;
  total_controls: number;
}

export interface RiskAssessment {
  security_posture_score: number;
  security_posture_level: string;
  overall_risk_score: number;
  overall_risk_level: string;
}

export interface AnalysisResults {
  analysis_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  overall_compliance_score: number;
  frameworks: FrameworkCoverage[];
  findings: Finding[];
  risk_assessment?: RiskAssessment;
  executive_summary?: string;
  completed_at?: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface ProgressEvent {
  event_type: string;
  timestamp: string;
  data: Record<string, unknown>;
  progress_percentage?: number;
  message?: string;
}

export interface ConnectionStatus {
  success: boolean;
  region: string;
  model_id: string;
  message: string;
  latency_ms?: number;
  error?: string;
}

export type AnalysisStatus = 'idle' | 'uploading' | 'analyzing' | 'completed' | 'error';

export const FRAMEWORKS = [
  { id: 'SOC2', name: 'SOC 2', description: 'Service Organization Control 2' },
  { id: 'ISO27001', name: 'ISO 27001', description: 'Information Security Management' },
  { id: 'NIST_CSF', name: 'NIST CSF', description: 'Cybersecurity Framework' },
  { id: 'HIPAA', name: 'HIPAA', description: 'Health Insurance Portability' },
  { id: 'GDPR', name: 'GDPR', description: 'General Data Protection Regulation' },
  { id: 'PCI_DSS', name: 'PCI DSS', description: 'Payment Card Industry Standard' },
] as const;
