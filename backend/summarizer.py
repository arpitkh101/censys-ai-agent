"""
AI-powered summarization engine for Censys host data
"""

import json
import time
import logging
import json
from typing import Dict, List, Any, Union
from datetime import datetime
import openai
from anthropic import Anthropic
import google.generativeai as genai
import os
import httpx
import asyncio

from models import (
    HostData, OverviewSummary, ServicesSummary, InfrastructureSummary, ServiceDetail,
    SeverityLevel, ProtocolType, HostOverview, MultiHostDataset, RiskyService, ServiceRecommendation
)

logger = logging.getLogger(__name__)

class CensysSummarizer:
    """AI-powered summarization engine for Censys host data"""
    
    def __init__(self):
        self.openai_client = None
        self.anthropic_client = None
        self.gemini_model = None
        self.last_processing_time = 0
        self.last_analysis_method = "rule_based"
        self.last_ai_model_used = None
        self.http_client = None
        
        # Initialize AI clients
        self._initialize_clients()
        
        # Load prompt templates
        self.prompts = self._load_prompt_templates()
    
    def _initialize_clients(self):
        """Initialize AI model clients with connection pooling"""
        try:
            # Initialize HTTP client with connection pooling
            self.http_client = httpx.Client(
                timeout=30.0,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
                http2=True  # Enable HTTP/2 for better performance
            )
            
            # OpenAI client
            if os.getenv("OPENAI_API_KEY"):
                self.openai_client = openai.OpenAI(
                    api_key=os.getenv("OPENAI_API_KEY"),
                    http_client=self.http_client
                )
                logger.info("OpenAI client initialized with connection pooling")
            
            # Anthropic client
            if os.getenv("ANTHROPIC_API_KEY"):
                self.anthropic_client = Anthropic(
                    api_key=os.getenv("ANTHROPIC_API_KEY"),
                    http_client=self.http_client
                )
                logger.info("Anthropic client initialized with connection pooling")
            
            # Google Gemini client
            if os.getenv("GEMINI_API_KEY"):
                genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
                self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                logger.info("Google Gemini client initialized")
                
        except Exception as e:
            logger.warning(f"Failed to initialize AI clients: {e}")
    
    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load optimized prompt templates for different summary types"""
        return {
            "combined": """# Censys Host Security Analysis Template

You are an expert cybersecurity analyst specializing in network reconnaissance and threat assessment. Analyze the provided Censys host data and generate a comprehensive security summary in JSON format.

## Analysis Instructions:
- **Prioritize critical security findings** that require immediate attention
- **Check each service for malware_detected field and if it is true, then include it in threat_context"
- **Correlate threat intelligence** with technical findings
- **Identify attack vectors** and potential threat actor TTPs
- **Provide actionable recommendations** with clear priority levels
- **Flag anomalies** in hosting patterns, configurations, or behaviors

Host Data:
{host_data}

IMPORTANT: You must respond with ONLY valid JSON. No additional text, explanations, or markdown formatting. Start your response with {{ and end with }}.

## Output Format:

{{
  "host_summary": {{
    "ip": "string",
    "location": "City, Country (ASN Country if different)",
    "hostname": "string (if available)",
    "risk_level": "critical|high|medium|low",
    "confidence": "high|medium|low",
    "threat_context": "brief sentence about threat actors, malware, or attack patterns if exists else empty string",
    "key_findings": [
      "brief critical finding 1",
      "brief critical finding 2"
    ],
    "immediate_action": "most critical recommendation with timeline"
  }},
  "services": [
    {{
      "port": number,
      "protocol": "string",
      "service_type": "string (e.g., remote_access|web_admin|database|c2_server|proxy|vpn|suspicious_custom)",
      "banner": "string (truncated if long)",
      "software": "product version (if available)",
      "security_status": "vulnerable|misconfigured|suspicious|secured",
      "critical_issues": [
        "critical issues 1 (could be a sentence about malware name, name of the threat actors, and threat type if present)",
        "critical issues 2: (could be CVE-XXXX-XXXX (CVSS: X.X) details)"
      ],
      "recommendation": [
        "recommendation1 to improve the service security if exists",
        "recommendation2 to improve the service security if exists"
      ]
    }}
  ],
  "infrastructure_analysis": {{
    "hosting_provider": "ASN name",
    "geographic_notes": "any location/ASN discrepancies or patterns",
    "certificate_issues": ["self-signed", "expired", "suspicious"],
    "network_behavior": "any unusual port combinations or service patterns"
  }}
}}

## Key Analysis Focus Areas:

Analyse each service separately

### MALWARE DETECTION:
Always check for malware_detected object in each service
If malware_detected exists: Extract name, type, confidence, threat_actors
Flag C2 servers, Cobalt Strike, RATs as CRITICAL risk
Include malware name and threat actors in threat_context

### Critical Threats (Immediate Action Required):
- **Active malware** (C2 servers, beacons, known malicious signatures)
- **Exploited vulnerabilities** (CVSS ≥ 9.0 OR known exploitation in wild)
- **Compromised indicators** (threat actor infrastructure, suspicious certificates)

### High Priority Issues:
- **Critical vulnerabilities** (CVSS 7.0-8.9)
- **Significant exposure** (sensitive services on public internet)
- **Authentication bypasses** or weak access controls
- **Suspicious configurations** (unusual ports, non-standard setups)

### Medium/Low Priority:
- **Medium vulnerabilities** (CVSS 4.0-6.9)
- **Configuration weaknesses** that increase attack surface
- **Missing security headers** or outdated software versions
- **Informational findings** for situational awareness

## Risk Level Guidelines:

- **CRITICAL**: Active malware OR known exploited CVE OR threat actor infrastructure
- **HIGH**: Critical vulnerability (CVSS ≥ 7.0) OR significant exposure OR multiple high-risk services
- **MEDIUM**: Medium vulnerabilities OR misconfigurations OR suspicious patterns
- **LOW**: Minor issues OR well-secured services OR informational findings only

## Special Considerations:

### Geographic Anomalies:
Flag when ASN country differs from geolocation (potential VPS/hosting service)

### Threat Intelligence Correlation:
- Match security labels to known attack patterns
- Identify threat actor TTPs from service combinations
- Correlate malware families with infrastructure patterns

### Service Pattern Analysis:
- Unusual port combinations that suggest specific toolkits
- Multiple web services on high ports (potential admin panels)
- Database services with weak access controls

## Analysis Quality Standards:
- **Confidence HIGH**: Multiple corroborating indicators, clear threat signatures
- **Confidence MEDIUM**: Some indicators present, moderate certainty
- **Confidence LOW**: Limited data or ambiguous indicators

Focus on delivering intelligence that enables rapid threat response and risk mitigation."""
        }
    
    async def generate_summaries(
        self, 
        host_data: Union[HostData, dict], 
        summary_types: List[str]
    ) -> Dict[str, Union[OverviewSummary, ServicesSummary, InfrastructureSummary]]:
        """Generate all summaries with a single AI call"""
        start_time = time.time()
        
        # Convert host data to JSON string for prompt
        if isinstance(host_data, dict):
            # Raw data - convert directly to JSON
            host_data_json = json.dumps(host_data, indent=2)
            logger.info(f"Raw data being sent to AI: {host_data_json[:500]}...")  # Log first 500 chars
        else:
            # Normalized HostData object
            host_data_json = host_data.model_dump_json(indent=2)
            logger.info(f"Normalized data being sent to AI: {host_data_json[:500]}...")  # Log first 500 chars
        
        # Make single AI call for all summaries
        try:
            ai_response, ai_model_used = await self._make_single_ai_call(host_data_json)
            
            if ai_response:
                # Parse the combined response
                response_data = json.loads(ai_response)
                summaries = self._create_all_summary_models(response_data, summary_types)
                self.last_analysis_method = "ai"
                self.last_ai_model_used = ai_model_used
                logger.info(f"Analysis completed using AI model: {ai_model_used}")
            else:
                # Fallback to rule-based summaries
                summaries = self._create_rule_based_summaries(host_data, summary_types)
                self.last_analysis_method = "rule_based"
                self.last_ai_model_used = None
                logger.info("Analysis completed using rule-based fallback")
                
        except Exception as e:
            logger.error(f"Failed to generate summaries: {e}")
            # Fallback to rule-based summaries - but we need normalized data for this
            # This should not happen in normal flow as main.py handles the fallback
            # with normalized data. This is just a safety net.
            if isinstance(host_data, dict):
                logger.warning("Cannot create rule-based summaries from raw dict data")
                # Create basic fallback summaries
                summaries = {}
                for summary_type in summary_types:
                    summaries[summary_type] = self._create_fallback_summary(summary_type, None)
            else:
                summaries = self._create_rule_based_summaries(host_data, summary_types)
                self.last_analysis_method = "rule_based"
                self.last_ai_model_used = None
            logger.info("Analysis completed using rule-based fallback due to error")
        
        self.last_processing_time = int((time.time() - start_time) * 1000)
        return summaries
    
    def generate_host_overview(self, host_data: HostData) -> HostOverview:
        """Generate overview information for a single host"""
        # Count vulnerabilities by severity
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_vulns = 0
        
        for service in host_data.services:
            for vuln in service.vulns:
                total_vulns += 1
                severity = vuln.severity.value.lower()
                if severity in vuln_counts:
                    vuln_counts[severity] += 1
        
        # Extract location info
        location_str = None
        if host_data.location:
            parts = []
            if host_data.location.city:
                parts.append(host_data.location.city)
            if host_data.location.country:
                parts.append(host_data.location.country)
            location_str = ", ".join(parts) if parts else None
        
        # Extract AS info
        asn = None
        as_name = None
        asn_country_code = None

        if host_data.autonomous_system:
            asn = host_data.autonomous_system.asn
            as_name = host_data.autonomous_system.name
            asn_country_code = host_data.autonomous_system.country_code
        
        # Extract hostname
        hostname = None
        if hasattr(host_data, 'dns') and host_data.dns and hasattr(host_data.dns, 'hostname'):
            hostname = host_data.dns.hostname
        
        # Extract ports and protocols
        open_ports = [service.port for service in host_data.services]
        protocols = list(set(service.protocol.value for service in host_data.services))
        
        # Identify risky services - Commented out for later use
        risky_services = []        
        # Determine risk level
        risk_level = host_data.threat_intelligence.risk_level if host_data.threat_intelligence else "UNKNOWN"
        
        return HostOverview(
            ip=host_data.ip,
            location=location_str,
            country_code=host_data.autonomous_system.country_code if host_data.autonomous_system else None,
            asn=asn,
            as_name=as_name,
            hostname=hostname,
            total_services=len(host_data.services),
            total_vulnerabilities=total_vulns,
            critical_vulnerabilities=vuln_counts["critical"],
            high_vulnerabilities=vuln_counts["high"],
            risk_level=risk_level,
            open_ports=open_ports,
            protocols=protocols,
            risky_services=risky_services
        )
    
    def analyze_multi_host_dataset(self, dataset: MultiHostDataset) -> List[HostOverview]:
        """Analyze multiple hosts and return overview information"""
        start_time = time.time()
        
        host_overviews = []
        for host_data in dataset.hosts:
            try:
                overview = self.generate_host_overview(host_data)
                host_overviews.append(overview)
            except Exception as e:
                logger.error(f"Failed to analyze host {host_data.ip}: {e}")
                # Create minimal overview for failed hosts
                host_overviews.append(HostOverview(
                    ip=host_data.ip,
                    location="Unknown",
                    total_services=0,
                    total_vulnerabilities=0,
                    risk_level="UNKNOWN"
                ))
        
        self.last_processing_time = int((time.time() - start_time) * 1000)
        return host_overviews
    
    async def _make_single_ai_call(self, host_data_json: str) -> tuple[str, str]:
        """Make a single AI call to get all summaries"""
        prompt = self.prompts["combined"].format(host_data=host_data_json)
        
        # Try AI models in order of preference
        ai_response = None
        ai_model_used = None
        
        if self.openai_client:
            try:
                ai_response = await self._call_openai(prompt)
                ai_model_used = "gpt-4o-mini"
                logger.info("OpenAI call successful")
            except Exception as e:
                logger.warning(f"OpenAI call failed: {e}")
        
        if not ai_response and self.anthropic_client:
            try:
                ai_response = await self._call_anthropic(prompt)
                ai_model_used = "claude-3-haiku"
                logger.info("Anthropic call successful")
            except Exception as e:
                logger.warning(f"Anthropic call failed: {e}")
        
        if not ai_response and self.gemini_model:
            try:
                ai_response = await self._call_gemini(prompt)
                ai_model_used = "gemini-1.5-flash"
                logger.info("Gemini call successful")
            except Exception as e:
                logger.warning(f"Gemini call failed: {e}")
        
        return ai_response, ai_model_used
    
    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        try:
            # OpenAI client is synchronous, so we need to run it in a thread
            import asyncio
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=4000
                )
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
    
    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic API"""
        try:
            response = await self.anthropic_client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=4000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text.strip()
        except Exception as e:
            logger.error(f"Anthropic API call failed: {e}")
            raise
    
    async def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API"""
        try:
            response = await self.gemini_model.generate_content_async(prompt)
            return response.text.strip()
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            raise
    
    def _create_all_summary_models(
        self, 
        response_data: Dict[str, Any], 
        summary_types: List[str]
    ) -> Dict[str, Union[OverviewSummary, ServicesSummary, InfrastructureSummary]]:
        """Create all summary models from new security analysis response"""
        summaries = {}
        
        # Extract data from new template structure
        host_summary = response_data.get("host_summary", {})
        services = response_data.get("services", [])
        infrastructure = response_data.get("infrastructure_analysis", {})
        
        for summary_type in summary_types:
            try:
                if summary_type == "overview":
                    summaries[summary_type] = self._create_overview_from_template(host_summary, services, infrastructure)                                                                                                 
                elif summary_type == "services":
                    summaries[summary_type] = self._create_services_from_template(host_summary, services, infrastructure)                                                                                                 
                elif summary_type == "infrastructure":
                    summaries[summary_type] = self._create_infrastructure_from_template(host_summary, services, infrastructure)                                                                                           
            except Exception as e:
                logger.error(f"Failed to create {summary_type} summary: {e}")
                    # Create fallback summary
                summaries[summary_type] = self._create_fallback_summary(summary_type, None)
        
        return summaries
    
    def _create_overview_from_template(self, host_summary: Dict, services: List, infrastructure: Dict) -> OverviewSummary:
        """Convert new template format to OverviewSummary"""
        return OverviewSummary(
            ip=host_summary.get("ip", "unknown"),
            location=host_summary.get("location", "Unknown"),
            hostname=host_summary.get("hostname"),
            risk_level=host_summary.get("risk_level", "low"),
            confidence=host_summary.get("confidence", "low"),
            threat_context=host_summary.get("threat_context"),
            key_findings=host_summary.get("key_findings", []),
            immediate_action=host_summary.get("immediate_action", "No immediate action required")
        )
    
    def _create_services_from_template(self, host_summary: Dict, services: List, infrastructure: Dict) -> ServicesSummary:
        """Convert new template format to ServicesSummary"""
        service_details = []
        
        for service in services:
            # Parse recommendations from AI response
            recommendations = []
            raw_recommendations = service.get("recommendation", [])
            
            if isinstance(raw_recommendations, list):
                for rec in raw_recommendations:
                    if isinstance(rec, str):
                        # Parse string format: "action with priority (HIGH/MEDIUM/LOW)"
                        priority = "MEDIUM"  # default
                        action = rec
                        
                        # Try to extract priority from the string
                        if "(HIGH)" in rec.upper():
                            priority = "HIGH"
                            action = rec.replace("(HIGH)", "").replace("(high)", "").strip()
                        elif "(MEDIUM)" in rec.upper():
                            priority = "MEDIUM"
                            action = rec.replace("(MEDIUM)", "").replace("(medium)", "").strip()
                        elif "(LOW)" in rec.upper():
                            priority = "LOW"
                            action = rec.replace("(LOW)", "").replace("(low)", "").strip()
                        
                        recommendations.append(ServiceRecommendation(
                            priority=priority,
                            action=action.strip()
                        ))
                    elif isinstance(rec, dict):
                        # Handle structured recommendation objects
                        recommendations.append(ServiceRecommendation(
                            priority=rec.get("priority", "MEDIUM"),
                            action=rec.get("action", ""),
                            description=rec.get("description")
                        ))
            elif isinstance(raw_recommendations, str):
                # Handle single string recommendation (backward compatibility)
                recommendations.append(ServiceRecommendation(
                    priority="MEDIUM",
                    action=raw_recommendations
                ))
            
            # If no recommendations found, add a default one
            if not recommendations:
                recommendations.append(ServiceRecommendation(
                    priority="MEDIUM",
                    action="Review service configuration"
                ))
            
            service_detail = ServiceDetail(
                port=service.get("port", 0),
                protocol=service.get("protocol", "UNKNOWN"),
                service_type=service.get("service_type", "unknown"),
                banner=service.get("banner"),
                software=service.get("software"),
                security_status=service.get("security_status", "unknown"),
                critical_issues=service.get("critical_issues", []),
                recommendations=recommendations
            )
            service_details.append(service_detail)
        
        return ServicesSummary(services=service_details)
    
    def _create_infrastructure_from_template(self, host_summary: Dict, services: List, infrastructure: Dict) -> InfrastructureSummary:
        """Convert new template format to InfrastructureSummary"""
        return InfrastructureSummary(
            hosting_provider=infrastructure.get("hosting_provider", "Unknown"),
            geographic_notes=infrastructure.get("geographic_notes"),
            certificate_issues=infrastructure.get("certificate_issues", []),
            network_behavior=infrastructure.get("network_behavior")
        )
    
    def _create_rule_based_summaries(
        self, 
        host_data: HostData, 
        summary_types: List[str]
    ) -> Dict[str, Union[OverviewSummary, ServicesSummary, InfrastructureSummary]]:
        """Create rule-based summaries as fallback"""
        summaries = {}
        
        for summary_type in summary_types:
            if summary_type == "overview":
                summaries[summary_type] = self._create_overview_summary_rules(host_data)
            elif summary_type == "services":
                summaries[summary_type] = self._create_services_summary_rules(host_data)
            elif summary_type == "infrastructure":
                summaries[summary_type] = self._create_infrastructure_summary_rules(host_data)
        
        return summaries
    
    def _create_overview_summary_rules(self, host_data: HostData) -> OverviewSummary:
        """Create overview summary using rule-based analysis"""
        # Analyze vulnerabilities for risk level
        critical_vulns = sum(1 for service in host_data.services 
                           for vuln in service.vulns 
                           if vuln.severity == SeverityLevel.CRITICAL)
        
        high_vulns = sum(1 for service in host_data.services 
                        for vuln in service.vulns 
                        if vuln.severity == SeverityLevel.HIGH)
        
        # Determine risk level
        if critical_vulns > 0:
            risk_level = "critical"
        elif high_vulns > 2:
            risk_level = "high"
        elif high_vulns > 0 or len(host_data.services) > 10:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Generate findings
        findings = []
        if critical_vulns > 0:
            findings.append(f"Critical vulnerabilities detected ({critical_vulns})")
        if high_vulns > 0:
            findings.append(f"High-severity vulnerabilities present ({high_vulns})")
        if len(host_data.services) > 5:
            findings.append(f"Multiple services exposed ({len(host_data.services)})")
        
        # Location-based findings
        if host_data.location:
            findings.append(f"Located in {host_data.location.country or 'Unknown country'}")
        
        # Create location string
        location_parts = []
        if host_data.location and host_data.location.city:
            location_parts.append(host_data.location.city)
        if host_data.location and host_data.location.country:
            location_parts.append(host_data.location.country)
        location = ", ".join(location_parts) if location_parts else "Unknown"
        
        # Immediate action
        if critical_vulns > 0:
            immediate_action = "Patch critical vulnerabilities immediately"
        elif high_vulns > 0:
            immediate_action = "Address high-severity vulnerabilities within 24 hours"
        else:
            immediate_action = "Conduct security assessment"
        
        return OverviewSummary(
            ip=host_data.ip,
            location=location,
            hostname=None,  # Would need additional data
            risk_level=risk_level,
            confidence="medium",
            key_findings=findings,
            immediate_action=immediate_action
        )
    
    def _create_services_summary_rules(self, host_data: HostData) -> ServicesSummary:
        """Create services summary using rule-based analysis"""
        service_details = []
        
        for service in host_data.services:
            # Determine security status based on vulnerabilities
            security_status = "secured"
            critical_issues = []
            
            for vuln in service.vulns:
                if vuln.severity == SeverityLevel.CRITICAL:
                    security_status = "vulnerable"
                    critical_issues.append(f"{vuln.id} (CRITICAL)")
                elif vuln.severity == SeverityLevel.HIGH:
                    security_status = "vulnerable"
                    critical_issues.append(f"{vuln.id} (HIGH)")
                elif vuln.severity == SeverityLevel.MEDIUM:
                    if security_status == "secured":
                        security_status = "misconfigured"
                    critical_issues.append(f"{vuln.id} (MEDIUM)")
            
            # Determine service type
            service_type = "unknown"
            if service.protocol.value in ["SSH", "TELNET"]:
                service_type = "remote_access"
            elif service.protocol.value in ["HTTP", "HTTPS"]:
                service_type = "web_server"
            elif service.protocol.value in ["MYSQL", "POSTGRESQL"]:
                service_type = "database"
            elif service.protocol.value == "FTP":
                service_type = "file_transfer"
            
            # Create software string
            software = None
            if service.software:
                sw = service.software[0]
                software = f"{sw.product} {sw.version}" if sw.product and sw.version else sw.product
            
            # Generate recommendation
            if security_status == "vulnerable":
                recommendation = "Patch vulnerabilities immediately (HIGH)"
            elif security_status == "misconfigured":
                recommendation = "Review and secure configuration (MEDIUM)"
            else:
                recommendation = "Monitor for security updates (LOW)"
            
            service_detail = ServiceDetail(
                port=service.port,
                protocol=service.protocol.value,
                service_type=service_type,
                banner=service.banner,
                software=software,
                security_status=security_status,
                critical_issues=critical_issues,
                recommendation=recommendation
            )
            service_details.append(service_detail)
        
        return ServicesSummary(services=service_details)
    
    def _create_infrastructure_summary_rules(self, host_data: HostData) -> InfrastructureSummary:
        """Create infrastructure summary using rule-based analysis"""
        # Determine hosting provider
        hosting_provider = "Unknown"
        if host_data.autonomous_system:
            hosting_provider = host_data.autonomous_system.name or f"AS{host_data.autonomous_system.asn}"
        
        # Check for geographic anomalies
        geographic_notes = None
        if host_data.location and host_data.autonomous_system:
            if host_data.location.country_code != host_data.autonomous_system.country_code:
                geographic_notes = f"Geolocation ({host_data.location.country_code}) differs from ASN country ({host_data.autonomous_system.country_code})"
        
        # Analyze network behavior
        network_behavior = None
        if len(host_data.services) > 5:
            network_behavior = "Multiple services exposed - potential attack surface"
        elif any(service.protocol.value in ["MYSQL", "POSTGRESQL"] for service in host_data.services):
            network_behavior = "Database services exposed on public internet"
        
        return InfrastructureSummary(
            hosting_provider=hosting_provider,
            geographic_notes=geographic_notes,
            certificate_issues=[],  # Would need certificate data
            network_behavior=network_behavior
        )
    
    def _create_fallback_summary(
        self, 
        summary_type: str, 
        host_data: HostData
    ) -> Union[OverviewSummary, ServicesSummary, InfrastructureSummary]:
        """Create a basic fallback summary"""
        if summary_type == "overview":
            return OverviewSummary(
                ip=host_data.ip if host_data else "unknown",
                location="Unknown",
                hostname=None,
                risk_level="unknown",
                confidence="low",
                key_findings=["Analysis service temporarily unavailable"],
                immediate_action="Retry analysis or contact support"
            )
        elif summary_type == "services":
            return ServicesSummary(services=[])
        elif summary_type == "infrastructure":
            return InfrastructureSummary(
                hosting_provider="Unknown",
                geographic_notes=None,
                certificate_issues=[],
                network_behavior=None
            )
        else:
            # Generic fallback
            return OverviewSummary(
                ip=host_data.ip if host_data else "unknown",
                location="Unknown",
                hostname=None,
                risk_level="unknown",
                confidence="low",
                key_findings=["Service temporarily unavailable"],
                immediate_action="Please retry"
            )
    
    async def generate_rule_based_summaries(
        self, 
        host_data: HostData, 
        summary_types: List[str]
    ) -> Dict[str, Union[OverviewSummary, ServicesSummary, InfrastructureSummary]]:
        """Generate rule-based summaries as fallback"""
        return self._create_rule_based_summaries(host_data, summary_types)
    
