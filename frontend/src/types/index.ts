// Type definitions for the Censys AI Agent frontend

export interface Coordinates {
  latitude: number;
  longitude: number;
}

export interface Location {
  continent?: string;
  country?: string;
  country_code?: string;
  city?: string;
  postal_code?: string;
  timezone?: string;
  province?: string;
  coordinates?: Coordinates;
}

export interface AutonomousSystem {
  asn: number;
  description?: string;
  bgp_prefix?: string;
  name?: string;
  country_code?: string;
}

export interface WhoisNetwork {
  handle?: string;
  name?: string;
  cidrs?: string[];
  updated?: string;
}

export interface Whois {
  network?: WhoisNetwork;
}

export interface SoftwareEvidence {
  data_path: string;
  found_value: string;
  literal_match: string;
}

export interface Software {
  source: string;
  confidence: number;
  evidence: SoftwareEvidence[];
  type: string[];
  part: string;
  product?: string;
  vendor?: string;
  version?: string;
  cpe?: string;
}

export interface CVEComponent {
  attack_complexity?: string;
  attack_vector?: string;
  availability_impact?: string;
  confidentiality_impact?: string;
  integrity_impact?: string;
  privileges_required?: string;
  scope?: string;
  user_interaction?: string;
}

export interface CVEMetrics {
  cvss_v30?: Record<string, any>;
  cvss_v31?: Record<string, any>;
  cvss_v40?: Record<string, any>;
  components?: CVEComponent;
}

export interface Vulnerability {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  kev?: boolean;
  metrics?: CVEMetrics;
  description?: string;
}

export interface Service {
  port: number;
  protocol: string;
  transport_protocol: 'tcp' | 'udp';
  banner?: string;
  banner_hash_sha256?: string;
  banner_hex?: string;
  software: Software[];
  vulns: Vulnerability[];
  labels: string[];
  ssh?: Record<string, any>;
  http?: Record<string, any>;
  https?: Record<string, any>;
  ftp?: Record<string, any>;
  smtp?: Record<string, any>;
  dns?: Record<string, any>;
  cert?: Record<string, any>;
  endpoints?: Record<string, any>[];
}

export interface HostData {
  ip: string;
  location?: Location;
  autonomous_system?: AutonomousSystem;
  whois?: Whois;
  services: Service[];
  last_updated?: string;
  scan_timestamp?: string;
}

export interface OverviewSummary {
  ip: string;
  location: string;
  hostname?: string;
  risk_level: string;
  confidence: string;
  threat_context?: string;
  key_findings: string[];
  immediate_action: string;
}

export interface ServiceRecommendation {
  priority: string;
  action: string;
  description?: string;
}

export interface ServiceDetail {
  port: number;
  protocol: string;
  service_type: string;
  banner?: string;
  software?: string;
  security_status: string;
  critical_issues: string[];
  recommendations: ServiceRecommendation[];
}

export interface ServicesSummary {
  services: ServiceDetail[];
}

export interface InfrastructureSummary {
  hosting_provider: string;
  geographic_notes?: string;
  certificate_issues: string[];
  network_behavior?: string;
}

export interface RiskyService {
  port: number;
  protocol: string;
  risk_reason: string;
  vulnerability_count: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
}

export interface HostOverview {
  ip: string;
  location?: string;
  country_code?: string;
  asn?: number;
  as_name?: string;
  hostname?: string;
  total_services: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  risk_level?: string;
  open_ports: number[];
  protocols: string[];
  risky_services: RiskyService[];
  full_host_data?: any;
}

export interface MultiHostOverviewResponse {
  total_hosts: number;
  timestamp: string;
  hosts_overview: HostOverview[];
  processing_time_ms: number;
  analysis_method: string;
  ai_model_used?: string;
  metadata?: any;
}

export interface SummaryResponse {
  host_ip: string;
  timestamp: string;
  summaries: {
    overview?: OverviewSummary;
    services?: ServicesSummary;
    infrastructure?: InfrastructureSummary;
  };
  processing_time_ms?: number;
  analysis_method?: string;
  ai_model_used?: string;
  metadata?: Record<string, any>;
}

export interface ApiError {
  detail: string;
  status_code?: number;
}

export interface UploadResponse {
  message: string;
  filename: string;
}

export type SummaryType = 'overview' | 'services' | 'infrastructure';
export type ExportFormat = 'pdf' | 'json' | 'txt';
