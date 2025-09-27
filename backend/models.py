"""
Pydantic models for Censys host data structure
Based on the official Censys Platform Host Dataset documentation
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum

class SeverityLevel(str, Enum):
    """CVE severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class TransportProtocol(str, Enum):
    """Transport protocols"""
    TCP = "tcp"
    UDP = "udp"

class ProtocolType(str, Enum):
    """Service protocols"""
    SSH = "SSH"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    FTP = "FTP"
    SMTP = "SMTP"
    DNS = "DNS"
    UNKNOWN = "UNKNOWN"

class Coordinates(BaseModel):
    """Geographic coordinates"""
    latitude: float = Field(..., description="Latitude coordinate")
    longitude: float = Field(..., description="Longitude coordinate")

class Location(BaseModel):
    """Geographic location information"""
    continent: Optional[str] = Field(None, description="Continent name")
    country: Optional[str] = Field(None, description="Country name")
    country_code: Optional[str] = Field(None, description="ISO country code")
    city: Optional[str] = Field(None, description="City name")
    postal_code: Optional[str] = Field(None, description="Postal/ZIP code")
    timezone: Optional[str] = Field(None, description="Timezone identifier")
    province: Optional[str] = Field(None, description="Province/state name")
    coordinates: Optional[Coordinates] = Field(None, description="Geographic coordinates")

class AutonomousSystem(BaseModel):
    """Autonomous System information"""
    asn: int = Field(..., description="Autonomous System Number")
    description: Optional[str] = Field(None, description="AS description")
    bgp_prefix: Optional[str] = Field(None, description="BGP prefix")
    name: Optional[str] = Field(None, description="AS name")
    country_code: Optional[str] = Field(None, description="AS country code")

class WhoisNetwork(BaseModel):
    """WHOIS network information"""
    handle: Optional[str] = Field(None, description="Network handle")
    name: Optional[str] = Field(None, description="Network name")
    cidrs: Optional[List[str]] = Field(None, description="CIDR blocks")
    updated: Optional[datetime] = Field(None, description="Last update timestamp")

class Whois(BaseModel):
    """WHOIS information"""
    network: Optional[WhoisNetwork] = Field(None, description="Network WHOIS data")

class SoftwareEvidence(BaseModel):
    """Evidence for software identification"""
    data_path: str = Field(..., description="Path to the data source")
    found_value: str = Field(..., description="Value found in the data")
    literal_match: str = Field(..., description="Literal match string")

class Software(BaseModel):
    """Software information"""
    source: str = Field(..., description="Source of software identification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    evidence: List[SoftwareEvidence] = Field(default_factory=list, description="Evidence for identification")
    type: List[str] = Field(default_factory=list, description="Software type categories")
    part: str = Field(..., description="Software part (a=application, o=operating system, h=hardware)")
    product: Optional[str] = Field(None, description="Product name")
    vendor: Optional[str] = Field(None, description="Vendor name")
    version: Optional[str] = Field(None, description="Version string")
    cpe: Optional[str] = Field(None, description="Common Platform Enumeration identifier")

class CVEComponent(BaseModel):
    """CVE component information"""
    attack_complexity: Optional[str] = Field(None, description="Attack complexity level")
    attack_vector: Optional[str] = Field(None, description="Attack vector")
    availability_impact: Optional[str] = Field(None, description="Availability impact")
    confidentiality_impact: Optional[str] = Field(None, description="Confidentiality impact")
    integrity_impact: Optional[str] = Field(None, description="Integrity impact")
    privileges_required: Optional[str] = Field(None, description="Privileges required")
    scope: Optional[str] = Field(None, description="Scope of the vulnerability")
    user_interaction: Optional[str] = Field(None, description="User interaction required")

class CVEMetrics(BaseModel):
    """CVE metrics and scoring"""
    cvss_v30: Optional[Dict[str, Any]] = Field(None, description="CVSS v3.0 metrics")
    cvss_v31: Optional[Dict[str, Any]] = Field(None, description="CVSS v3.1 metrics")
    cvss_v40: Optional[Dict[str, Any]] = Field(None, description="CVSS v4.0 metrics")
    components: Optional[CVEComponent] = Field(None, description="CVE components")

class Vulnerability(BaseModel):
    """Vulnerability information"""
    id: str = Field(..., description="CVE ID")
    severity: SeverityLevel = Field(..., description="Severity level")
    kev: Optional[bool] = Field(None, description="Known Exploited Vulnerability flag")
    metrics: Optional[CVEMetrics] = Field(None, description="CVE metrics and scoring")
    description: Optional[str] = Field(None, description="Vulnerability description")

class Service(BaseModel):
    """Service information"""
    port: int = Field(..., description="Port number")
    protocol: ProtocolType = Field(..., description="Service protocol")
    transport_protocol: TransportProtocol = Field(..., description="Transport protocol")
    banner: Optional[str] = Field(None, description="Service banner")
    banner_hash_sha256: Optional[str] = Field(None, description="SHA256 hash of banner")
    banner_hex: Optional[str] = Field(None, description="Hex representation of banner")
    software: List[Software] = Field(default_factory=list, description="Identified software")
    vulns: List[Vulnerability] = Field(default_factory=list, description="Associated vulnerabilities")
    labels: List[str] = Field(default_factory=list, description="Service labels")
    
    # Protocol-specific data (nested objects)
    ssh: Optional[Dict[str, Any]] = Field(None, description="SSH-specific data")
    http: Optional[Dict[str, Any]] = Field(None, description="HTTP-specific data")
    https: Optional[Dict[str, Any]] = Field(None, description="HTTPS-specific data")
    ftp: Optional[Dict[str, Any]] = Field(None, description="FTP-specific data")
    smtp: Optional[Dict[str, Any]] = Field(None, description="SMTP-specific data")
    dns: Optional[Dict[str, Any]] = Field(None, description="DNS-specific data")
    
    # Certificate information
    cert: Optional[Dict[str, Any]] = Field(None, description="Certificate data")
    
    # HTTP endpoints (for web services)
    endpoints: Optional[List[Dict[str, Any]]] = Field(None, description="HTTP endpoints")

class ThreatIntelligence(BaseModel):
    """Threat intelligence information"""
    security_labels: Optional[List[str]] = Field(None, description="Security labels")
    risk_level: Optional[str] = Field(None, description="Risk level assessment")

class HostData(BaseModel):
    """Complete host data structure from Censys"""
    ip: str = Field(..., description="IP address")
    location: Optional[Location] = Field(None, description="Geographic location")
    autonomous_system: Optional[AutonomousSystem] = Field(None, description="AS information")
    whois: Optional[Whois] = Field(None, description="WHOIS data")
    services: List[Service] = Field(default_factory=list, description="Detected services")
    threat_intelligence: Optional[ThreatIntelligence] = Field(None, description="Threat intelligence data")
    
    # Additional metadata
    last_updated: Optional[datetime] = Field(None, description="Last scan timestamp")
    scan_timestamp: Optional[datetime] = Field(None, description="Scan timestamp")
    
    @validator('ip')
    def validate_ip(cls, v):
        """Basic IP validation"""
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')

class SummaryRequest(BaseModel):
    """Request for summary generation"""
    host_data: HostData = Field(..., description="Host data to summarize")
    summary_types: List[str] = Field(
        default=["executive", "technical", "security"],
        description="Types of summaries to generate"
    )
    custom_instructions: Optional[str] = Field(None, description="Custom summarization instructions")

class ExecutiveSummary(BaseModel):
    """Executive-level summary"""
    risk_level: str = Field(..., description="Overall risk level")
    business_impact: str = Field(..., description="Business impact assessment")
    key_findings: List[str] = Field(..., description="Key findings for executives")
    recommendations: List[str] = Field(..., description="High-level recommendations")
    compliance_notes: Optional[List[str]] = Field(None, description="Compliance considerations")

class TechnicalSummary(BaseModel):
    """Technical deep-dive summary"""
    service_analysis: Dict[str, Any] = Field(..., description="Detailed service analysis")
    configuration_issues: List[str] = Field(..., description="Configuration problems")
    software_inventory: Dict[str, Any] = Field(..., description="Software inventory and versions")
    network_analysis: Dict[str, Any] = Field(..., description="Network infrastructure analysis")
    technical_recommendations: List[str] = Field(..., description="Technical recommendations")

class SecuritySummary(BaseModel):
    """Security-focused summary"""
    vulnerability_summary: Dict[str, Any] = Field(..., description="Vulnerability overview")
    critical_issues: List[str] = Field(..., description="Critical security issues")
    exploitability_assessment: str = Field(..., description="Exploitability assessment")
    remediation_priority: List[str] = Field(..., description="Remediation priorities")
    threat_indicators: List[str] = Field(..., description="Potential threat indicators")

class OverviewSummary(BaseModel):
    """Host overview summary"""
    ip: str = Field(..., description="Host IP address")
    location: str = Field(..., description="Location (City, Country)")
    hostname: Optional[str] = Field(None, description="Hostname if available")
    risk_level: str = Field(..., description="Risk level: critical|high|medium|low")
    confidence: str = Field(..., description="Confidence level: high|medium|low")
    threat_context: Optional[str] = Field(None, description="Threat context sentence from AI analysis")
    key_findings: List[str] = Field(..., description="Key critical findings")
    immediate_action: str = Field(..., description="Most critical recommendation with timeline")

class ServiceRecommendation(BaseModel):
    """Individual service recommendation"""
    priority: str = Field(..., description="Priority level: HIGH|MEDIUM|LOW")
    action: str = Field(..., description="Specific action to take")
    description: Optional[str] = Field(None, description="Additional details about the recommendation")

class ServiceDetail(BaseModel):
    """Individual service analysis"""
    port: int = Field(..., description="Service port number")
    protocol: str = Field(..., description="Service protocol")
    service_type: str = Field(..., description="Service type (e.g., remote_access, web_server, database)")
    banner: Optional[str] = Field(None, description="Service banner (truncated if long)")
    software: Optional[str] = Field(None, description="Software product and version")
    security_status: str = Field(..., description="Security status: vulnerable|misconfigured|suspicious|secured")
    critical_issues: List[str] = Field(default_factory=list, description="Critical issues (CVEs, malware, misconfigurations)")
    recommendations: List[ServiceRecommendation] = Field(default_factory=list, description="Multiple recommendations with priorities")

class ServicesSummary(BaseModel):
    """Services analysis summary"""
    services: List[ServiceDetail] = Field(..., description="List of service analyses")

class InfrastructureSummary(BaseModel):
    """Infrastructure analysis summary"""
    hosting_provider: str = Field(..., description="ASN name/hosting provider")
    geographic_notes: Optional[str] = Field(None, description="Location/ASN discrepancies or patterns")
    certificate_issues: List[str] = Field(default_factory=list, description="Certificate issues")
    network_behavior: Optional[str] = Field(None, description="Unusual port combinations or service patterns")

class RiskyService(BaseModel):
    """Information about a risky service"""
    port: int = Field(..., description="Service port")
    protocol: str = Field(..., description="Service protocol")
    risk_reason: str = Field(..., description="Reason why this service is risky")
    vulnerability_count: int = Field(0, description="Number of vulnerabilities")
    critical_vulnerabilities: int = Field(0, description="Number of critical vulnerabilities")
    high_vulnerabilities: int = Field(0, description="Number of high vulnerabilities")

class HostOverview(BaseModel):
    """Overview information for a single host"""
    ip: str = Field(..., description="Host IP address")
    location: Optional[str] = Field(None, description="Host location (city, country)")
    country_code: Optional[str] = Field(None, description="Country code")
    asn: Optional[int] = Field(None, description="Autonomous System Number")
    as_name: Optional[str] = Field(None, description="AS name")
    hostname: Optional[str] = Field(None, description="Hostname if available")
    total_services: int = Field(0, description="Total number of services")
    total_vulnerabilities: int = Field(0, description="Total number of vulnerabilities")
    critical_vulnerabilities: int = Field(0, description="Number of critical vulnerabilities")
    high_vulnerabilities: int = Field(0, description="Number of high vulnerabilities")
    risk_level: Optional[str] = Field(None, description="Overall risk level")
    open_ports: List[int] = Field(default_factory=list, description="List of open ports")
    protocols: List[str] = Field(default_factory=list, description="List of protocols")
    risky_services: List[RiskyService] = Field(default_factory=list, description="List of risky services")
    
    class Config:
        extra = "allow"

class MultiHostDataset(BaseModel):
    """Model for multi-host dataset"""
    metadata: Optional[Dict[str, Any]] = Field(None, description="Dataset metadata")
    hosts: List[HostData] = Field(..., description="List of host data")

class MultiHostOverviewResponse(BaseModel):
    """Response for multi-host overview analysis"""
    total_hosts: int = Field(..., description="Total number of hosts")
    timestamp: str = Field(..., description="Analysis timestamp")
    hosts_overview: List[HostOverview] = Field(..., description="Overview of all hosts")
    processing_time_ms: int = Field(..., description="Processing time in milliseconds")
    analysis_method: str = Field(..., description="Method used for analysis")
    ai_model_used: Optional[str] = Field(None, description="AI model used if applicable")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class SummaryResponse(BaseModel):
    """Response containing generated summaries"""
    host_ip: str = Field(..., description="Host IP address")
    timestamp: str = Field(..., description="Generation timestamp")
    summaries: Dict[str, Union[OverviewSummary, ServicesSummary, InfrastructureSummary]] = Field(
        ..., description="Generated summaries by type"
    )
    processing_time_ms: Optional[int] = Field(None, description="Processing time in milliseconds")
    analysis_method: str = Field(..., description="Method used for analysis: 'ai' or 'rule_based'")
    ai_model_used: Optional[str] = Field(None, description="AI model used if analysis_method is 'ai'")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
