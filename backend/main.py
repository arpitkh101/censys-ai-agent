"""
Censys AI Agent - FastAPI Backend
Intelligent Host Data Summarization Service
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, FileResponse, Response
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import uvicorn
import os
import io
import time
from datetime import datetime
import logging

from models import HostData, SummaryRequest, SummaryResponse, OverviewSummary, ServicesSummary, InfrastructureSummary, MultiHostDataset, MultiHostOverviewResponse, HostOverview
from summarizer import CensysSummarizer
from export_service import ExportService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Censys AI Agent",
    description="Intelligent Host Data Summarization Service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add compression middleware for faster responses
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the summarizer and export service
summarizer = CensysSummarizer()
export_service = ExportService()

def normalize_hosts_with_error_handling(hosts: List[Dict[str, Any]]) -> tuple[List[HostData], List[Dict[str, Any]]]:
    """Normalize multiple hosts with error handling, skipping problematic ones"""
    normalized_hosts = []
    skipped_hosts = []
    
    for i, host in enumerate(hosts):
        try:
            logger.info(f"Processing host {i+1}: {host.get('ip', 'unknown')}")
            normalized_host = normalize_host_data(host)
            normalized_hosts.append(normalized_host)
        except Exception as e:
            host_ip = host.get('ip', f'host_{i+1}')
            logger.warning(f"Skipping host {i+1} ({host_ip}) due to error: {str(e)}")
            logger.debug(f"Host data structure: {list(host.keys()) if isinstance(host, dict) else type(host)}")
            skipped_hosts.append({
                'index': i+1,
                'ip': host_ip,
                'error': str(e)
            })
            continue
    
    # Log skipped hosts if any
    if skipped_hosts:
        logger.warning(f"Skipped {len(skipped_hosts)} hosts due to validation errors")
        for skipped in skipped_hosts:
            logger.warning(f"  - Host {skipped['index']} ({skipped['ip']}): {skipped['error']}")
    
    return normalized_hosts, skipped_hosts

def normalize_host_data(host_data: Dict[str, Any]) -> HostData:
    """Normalize host data to match our models with robust error handling"""
    try:
        # Check if this is a single host object or a host with additional metadata
        # If it has 'metadata' and 'risk_level' at top level, it might be a processed host
        if 'metadata' in host_data and 'risk_level' in host_data and 'ip' not in host_data:
            # This looks like a processed host object, extract the actual host data
            # Look for nested host data or reconstruct from available fields
            logger.warning("Detected processed host data structure, attempting to extract host information")
            # For now, we'll try to use the data as-is but ensure we have an IP
            if 'ip' not in host_data:
                # Try to extract IP from other fields or generate a placeholder
                host_data['ip'] = host_data.get('host_ip', 'unknown')
        
        # Ensure we have a required IP field
        if 'ip' not in host_data or not host_data['ip']:
            raise ValueError("Host data must contain an 'ip' field")
        
        # Ensure IP is a string
        host_data['ip'] = str(host_data['ip'])
        
    except Exception as e:
        logger.error(f"Error in initial host data validation: {str(e)}")
        raise ValueError(f"Invalid host data structure: {str(e)}")
    
    # Normalize services with robust error handling
    normalized_services = []
    for service_idx, service in enumerate(host_data.get('services', [])):
        try:
            # Ensure service is a dictionary
            if not isinstance(service, dict):
                logger.warning(f"Service {service_idx} is not a dictionary, skipping")
                continue
            
            # Normalize vulnerabilities with error handling
            normalized_vulns = []
            for vuln_idx, vuln in enumerate(service.get('vulnerabilities', [])):
                try:
                    # Ensure vulnerability is a dictionary
                    if not isinstance(vuln, dict):
                        logger.warning(f"Vulnerability {vuln_idx} in service {service_idx} is not a dictionary, skipping")
                        continue
                    
                    # Ensure vulnerability ID is always a string
                    vuln_id = vuln.get('cve_id') or vuln.get('id') or 'UNKNOWN'
                    if vuln_id is None:
                        vuln_id = 'UNKNOWN'
                    
                    # Ensure severity is always a string
                    severity = vuln.get('severity') or 'UNKNOWN'
                    if severity is None:
                        severity = 'UNKNOWN'
                    
                    # Ensure CVSS score is valid
                    cvss_score = vuln.get('cvss_score')
                    if cvss_score is not None:
                        try:
                            cvss_score = float(cvss_score)
                        except (ValueError, TypeError):
                            cvss_score = None
                    
                    normalized_vuln = {
                        'id': str(vuln_id),
                        'severity': str(severity).upper(),
                        'cvss_score': cvss_score,
                        'description': vuln.get('description'),
                        'kev': bool(vuln.get('kev', False))
                    }
                    normalized_vulns.append(normalized_vuln)
                    
                except Exception as e:
                    logger.warning(f"Error processing vulnerability {vuln_idx} in service {service_idx}: {str(e)}")
                    continue
        
            # Normalize software with error handling
            normalized_software = []
            for sw_idx, software in enumerate(service.get('software', [])):
                try:
                    # Ensure software is a dictionary
                    if not isinstance(software, dict):
                        logger.warning(f"Software {sw_idx} in service {service_idx} is not a dictionary, skipping")
                        continue
                    
                    # Ensure confidence is a valid float
                    confidence = software.get('confidence', 0.0)
                    if confidence is not None:
                        try:
                            confidence = float(confidence)
                        except (ValueError, TypeError):
                            confidence = 0.0
                    
                    normalized_sw = {
                        'product': software.get('product'),
                        'vendor': software.get('vendor'),
                        'version': software.get('version'),
                        'source': software.get('source', 'unknown'),
                        'confidence': confidence,
                        'part': software.get('part', 'a')
                    }
                    normalized_software.append(normalized_sw)
                    
                except Exception as e:
                    logger.warning(f"Error processing software {sw_idx} in service {service_idx}: {str(e)}")
                    continue
        
            # Map protocol names
            protocol_mapping = {
                'MYSQL': 'UNKNOWN',  # Map unsupported protocols to UNKNOWN
                'SSH': 'SSH',
                'HTTP': 'HTTP',
                'HTTPS': 'HTTPS',
                'FTP': 'FTP',
                'SMTP': 'SMTP',
                'DNS': 'DNS'
            }
            
            # Ensure port is valid
            port = service.get('port')
            if port is not None:
                try:
                    port = int(port)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid port value in service {service_idx}: {port}")
                    port = None
            
            # Ensure labels is a list
            labels = service.get('labels', [])
            if not isinstance(labels, list):
                labels = []
            
            normalized_service = {
                'port': port,
                'protocol': protocol_mapping.get(service.get('protocol'), 'UNKNOWN'),
                'transport_protocol': 'tcp',  # Default to TCP (single value, not list)
                'banner': service.get('banner'),
                'software': normalized_software,
                'vulns': normalized_vulns,
                'labels': labels
            }
            normalized_services.append(normalized_service)
            
        except Exception as e:
            logger.warning(f"Error processing service {service_idx}: {str(e)}")
            continue
    
    # Create normalized host data with error handling
    normalized_host = {
        'ip': host_data.get('ip'),
        'location': host_data.get('location'),
        'autonomous_system': host_data.get('autonomous_system'),
        'services': normalized_services,
        'dns': host_data.get('dns'),
        'certificates': host_data.get('certificates', []),
        'operating_system': host_data.get('operating_system'),
        'threat_intelligence': host_data.get('threat_intelligence')
    }
    
    return HostData(**normalized_host)

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "Censys AI Agent is running", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "censys-ai-agent"
    }

@app.post("/api/summarize", response_model=SummaryResponse)
async def summarize_host_data(
    host_data: HostData,
    summary_types: List[str] = ["overview", "services", "infrastructure"]
):
    """
    Generate intelligent summaries from Censys host data
    
    Args:
        host_data: Structured host data from Censys
        summary_types: Types of summaries to generate
    
    Returns:
        SummaryResponse with requested summary types
    """
    try:
        logger.info(f"Processing host data for IP: {host_data.ip}")
        
        summaries = await summarizer.generate_summaries(host_data, summary_types)
        
        return SummaryResponse(
            host_ip=host_data.ip,
            timestamp=datetime.utcnow().isoformat(),
            summaries=summaries,
            processing_time_ms=summarizer.last_processing_time,
            analysis_method=summarizer.last_analysis_method,
            ai_model_used=summarizer.last_ai_model_used
        )
        
    except Exception as e:
        logger.error(f"Error processing host data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Summarization failed: {str(e)}")

@app.post("/api/summarize/upload")
async def summarize_from_file(
    file: UploadFile = File(...),
    summary_types: str = Form("overview,services,infrastructure")
):
    """
    Upload and process a JSON file containing Censys host data
    """
    try:
        if not file.filename.endswith('.json'):
            raise HTTPException(status_code=400, detail="Only JSON files are supported")
        
        content = await file.read()
        data = json.loads(content.decode('utf-8'))
        
        # Handle different JSON structures
        if 'result' in data:
            host_data = HostData(**data['result'])
        elif 'resource' in data:
            host_data = HostData(**data['resource'])
        else:
            host_data = HostData(**data)
        
        summary_types_list = [s.strip() for s in summary_types.split(',')]
        summaries = await summarizer.generate_summaries(host_data, summary_types_list)
        
        return SummaryResponse(
            host_ip=host_data.ip,
            timestamp=datetime.utcnow().isoformat(),
            summaries=summaries,
            processing_time_ms=summarizer.last_processing_time,
            analysis_method=summarizer.last_analysis_method,
            ai_model_used=summarizer.last_ai_model_used
        )
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    except Exception as e:
        logger.error(f"Error processing uploaded file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")

@app.post("/api/summarize/bulk")
async def summarize_bulk_hosts(
    hosts_data: List[HostData],
    summary_types: List[str] = ["overview", "services", "infrastructure"]
):
    """
    Process multiple host records in parallel for maximum speed
    """
    try:
        import asyncio
        
        async def process_single_host(host_data: HostData) -> SummaryResponse:
            """Process a single host asynchronously"""
            summaries = await summarizer.generate_summaries(host_data, summary_types)
            return SummaryResponse(
                host_ip=host_data.ip,
                timestamp=datetime.utcnow().isoformat(),
                summaries=summaries,
                processing_time_ms=summarizer.last_processing_time
            )
        
        # Process all hosts in parallel (up to 10 concurrent)
        semaphore = asyncio.Semaphore(10)
        
        async def process_with_semaphore(host_data: HostData):
            async with semaphore:
                return await process_single_host(host_data)
        
        # Execute all tasks concurrently
        tasks = [process_with_semaphore(host_data) for host_data in hosts_data]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log them
        successful_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error processing host {hosts_data[i].ip}: {result}")
            else:
                successful_results.append(result)
        
        return {
            "total_hosts": len(hosts_data),
            "processed_hosts": len(successful_results),
            "failed_hosts": len(hosts_data) - len(successful_results),
            "results": successful_results,
            "batch_timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error processing bulk data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Bulk processing failed: {str(e)}")

@app.post("/api/analyze-hosts", response_model=MultiHostOverviewResponse)
async def analyze_hosts(request: dict):
    """
    Unified endpoint for analyzing hosts (single or multi-host JSONs).
    Always expects {hosts: [...]} format.
    AI-first analysis with rule-based fallback.
    """
    try:
        start_time = time.time()
        
        # Ensure the data has the expected structure
        if 'hosts' not in request:
            raise HTTPException(status_code=400, detail="JSON must contain 'hosts' array")
        
        if not isinstance(request['hosts'], list):
            raise HTTPException(status_code=400, detail="'hosts' must be an array")
        
        if len(request['hosts']) == 0:
            raise HTTPException(status_code=400, detail="'hosts' array cannot be empty")
        
        # Normalize host data for each host with error handling
        normalized_hosts, skipped_hosts = normalize_hosts_with_error_handling(request['hosts'])
        
        # Check if we have any valid hosts
        if not normalized_hosts:
            raise HTTPException(status_code=400, detail="No valid hosts could be processed from the provided data")
        
        # Create normalized dataset
        normalized_dataset = MultiHostDataset(
            metadata=request.get('metadata'),
            hosts=normalized_hosts
        )
        
        # Generate host overviews (rule-based for cards)
        host_overviews = summarizer.analyze_multi_host_dataset(normalized_dataset)
        
        # Store full host data for detailed analysis
        for i, overview in enumerate(host_overviews):
            # Add full_host_data as an extra attribute
            setattr(overview, 'full_host_data', request['hosts'][i])
        
        processing_time = int((time.time() - start_time) * 1000)
        
        return MultiHostOverviewResponse(
            total_hosts=len(host_overviews),
            timestamp=datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            hosts_overview=host_overviews,
            processing_time_ms=processing_time,
            analysis_method="rule_based",  # Overview is always rule-based
            ai_model_used=None,
            metadata=request.get('metadata')
        )
        
    except Exception as e:
        logger.error(f"Host analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Host analysis failed: {str(e)}")

@app.post("/api/analyze-hosts/upload", response_model=MultiHostOverviewResponse)
async def analyze_hosts_from_file(file: UploadFile = File(...)):
    """
    Unified endpoint for analyzing hosts from uploaded file.
    Always expects {hosts: [...]} format.
    AI-first analysis with rule-based fallback.
    """
    try:
        if not file.filename.endswith('.json'):
            raise HTTPException(status_code=400, detail="Only JSON files are supported")
        
        content = await file.read()
        data = json.loads(content.decode('utf-8'))
        
        # Ensure the data has the expected structure
        if 'hosts' not in data:
            raise HTTPException(status_code=400, detail="JSON must contain 'hosts' array")
        
        if not isinstance(data['hosts'], list):
            raise HTTPException(status_code=400, detail="'hosts' must be an array")
        
        if len(data['hosts']) == 0:
            raise HTTPException(status_code=400, detail="'hosts' array cannot be empty")
        
        # Log the total number of hosts in the file
        logger.info(f"File contains {len(data['hosts'])} hosts total")
        
        # Normalize and create MultiHostDataset with error handling
        normalized_hosts, skipped_hosts = normalize_hosts_with_error_handling(data['hosts'])
        
        # Log processing results
        logger.info(f"Successfully processed {len(normalized_hosts)} hosts, skipped {len(skipped_hosts)} hosts")
        
        # Check if we have any valid hosts
        if not normalized_hosts:
            raise HTTPException(status_code=400, detail="No valid hosts could be processed from the uploaded file")
        
        dataset = MultiHostDataset(
            metadata=data.get('metadata'),
            hosts=normalized_hosts
        )
        
        # Process the dataset directly
        start_time = time.time()
        
        # Generate host overviews (rule-based for cards)
        host_overviews = summarizer.analyze_multi_host_dataset(dataset)
        
        # Store full host data for detailed analysis
        for i, overview in enumerate(host_overviews):
            # Add full_host_data as an extra attribute - use original raw data, not normalized
            setattr(overview, 'full_host_data', data['hosts'][i])
        
        processing_time = int((time.time() - start_time) * 1000)
        
        return MultiHostOverviewResponse(
            total_hosts=len(host_overviews),
            timestamp=datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            hosts_overview=host_overviews,
            processing_time_ms=processing_time,
            analysis_method="rule_based",  # Overview is always rule-based
            ai_model_used=None,
            metadata=data.get('metadata')
        )
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    except Exception as e:
        logger.error(f"File analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")

@app.post("/api/analyze-hosts/paste", response_model=MultiHostOverviewResponse)
async def analyze_hosts_from_paste(request: dict):
    """
    Unified endpoint for analyzing hosts from pasted JSON.
    Always expects {hosts: [...]} format.
    AI-first analysis with rule-based fallback.
    """
    try:
        # Ensure the data has the expected structure
        if 'hosts' not in request:
            raise HTTPException(status_code=400, detail="JSON must contain 'hosts' array")
        
        if not isinstance(request['hosts'], list):
            raise HTTPException(status_code=400, detail="'hosts' must be an array")
        
        if len(request['hosts']) == 0:
            raise HTTPException(status_code=400, detail="'hosts' array cannot be empty")
        
        # Normalize and create MultiHostDataset
        normalized_hosts = []
        for i, host in enumerate(request['hosts']):
            try:
                logger.info(f"Processing host {i+1}: {host.get('ip', 'unknown')}")
                normalized_host = normalize_host_data(host)
                normalized_hosts.append(normalized_host)
            except Exception as e:
                logger.error(f"Error normalizing host {i+1}: {str(e)}")
                logger.error(f"Host data structure: {list(host.keys()) if isinstance(host, dict) else type(host)}")
                raise HTTPException(status_code=400, detail=f"Error processing host {i+1}: {str(e)}")
        
        dataset = MultiHostDataset(
            metadata=request.get('metadata'),
            hosts=normalized_hosts
        )
        
        # Process the dataset directly
        start_time = time.time()
        
        # Generate host overviews (rule-based for cards)
        host_overviews = summarizer.analyze_multi_host_dataset(dataset)
        
        # Store full host data for detailed analysis
        for i, overview in enumerate(host_overviews):
            # Add full_host_data as an extra attribute
            setattr(overview, 'full_host_data', request['hosts'][i])
        
        processing_time = int((time.time() - start_time) * 1000)
        
        return MultiHostOverviewResponse(
            total_hosts=len(host_overviews),
            timestamp=datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            hosts_overview=host_overviews,
            processing_time_ms=processing_time,
            analysis_method="rule_based",  # Overview is always rule-based
            ai_model_used=None,
            metadata=request.get('metadata')
        )
        
    except Exception as e:
        logger.error(f"Paste analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Paste analysis failed: {str(e)}")

@app.post("/api/summarize_host", response_model=SummaryResponse)
async def summarize_host(request: dict):
    """
    Summarize a single host - input = single host JSON, output = structured summary.
    This endpoint matches the TODO requirement.
    """
    try:
        if 'host_data' not in request:
            raise HTTPException(status_code=400, detail="host_data is required")
        
        # Normalize host data
        normalized_host_data = normalize_host_data(request['host_data'])
        host_data = normalized_host_data
        
        # Try AI analysis first
        try:
            summaries = await summarizer.generate_summaries(
                host_data, 
                request.get('summary_types', ['overview', 'services', 'infrastructure'])
            )
            analysis_method = "ai"
            ai_model_used = summarizer.last_ai_model_used
        except Exception as ai_error:
            logger.warning(f"AI analysis failed for {host_data.ip}, falling back to rule-based: {ai_error}")
            # Fallback to rule-based analysis
            summaries = await summarizer.generate_rule_based_summaries(
                host_data,
                request.get('summary_types', ['overview', 'services', 'infrastructure'])
            )
            analysis_method = "rule_based"
            ai_model_used = None
        
        return SummaryResponse(
            host_ip=host_data.ip,
            timestamp=datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            summaries=summaries,
            processing_time_ms=summarizer.last_processing_time,
            analysis_method=analysis_method,
            ai_model_used=ai_model_used
        )
        
    except Exception as e:
        logger.error(f"Host summarization failed: {e}")
        raise HTTPException(status_code=500, detail=f"Host summarization failed: {str(e)}")

@app.post("/api/summarize_all", response_model=MultiHostOverviewResponse)
async def summarize_all(request: dict):
    """
    Summarize all hosts in dataset - input = dataset, output = array of summaries.
    This endpoint matches the TODO requirement.
    """
    try:
        # Ensure the data has the expected structure
        if 'hosts' not in request:
            raise HTTPException(status_code=400, detail="JSON must contain 'hosts' array")
        
        if not isinstance(request['hosts'], list):
            raise HTTPException(status_code=400, detail="'hosts' must be an array")
        
        if len(request['hosts']) == 0:
            raise HTTPException(status_code=400, detail="'hosts' array cannot be empty")
        
        # Normalize host data for each host with error handling
        normalized_hosts, skipped_hosts = normalize_hosts_with_error_handling(request['hosts'])
        
        # Check if we have any valid hosts
        if not normalized_hosts:
            raise HTTPException(status_code=400, detail="No valid hosts could be processed from the provided data")
        
        # Create normalized dataset
        normalized_dataset = MultiHostDataset(
            metadata=request.get('metadata'),
            hosts=normalized_hosts
        )
        
        # Generate host overviews (rule-based for cards)
        host_overviews = summarizer.analyze_multi_host_dataset(normalized_dataset)
        
        # Store full host data for detailed analysis
        for i, overview in enumerate(host_overviews):
            # Add full_host_data as an extra attribute
            setattr(overview, 'full_host_data', request['hosts'][i])
        
        processing_time = int((time.time() - time.time()) * 1000)  # Will be set by summarizer
        
        return MultiHostOverviewResponse(
            total_hosts=len(host_overviews),
            timestamp=datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            hosts_overview=host_overviews,
            processing_time_ms=summarizer.last_processing_time,
            analysis_method="rule_based",  # Overview is always rule-based
            ai_model_used=None,
            metadata=request.get('metadata')
        )
        
    except Exception as e:
        logger.error(f"Summarize all failed: {e}")
        raise HTTPException(status_code=500, detail=f"Summarize all failed: {str(e)}")

@app.post("/api/analyze-hosts/individual/{host_ip}", response_model=SummaryResponse)
async def analyze_individual_host(host_ip: str, request: dict):
    """
    Analyze individual host with AI-first approach and rule-based fallback.
    """
    try:
        if 'host_data' not in request:
            raise HTTPException(status_code=400, detail="host_data is required")
        
        # Get raw host data for AI analysis
        raw_host_data = request['host_data']
        
        # Normalize host data for rule-based fallback
        normalized_host_data = normalize_host_data(request['host_data'])
        
        # Try AI analysis first with raw data
        try:
            summaries = await summarizer.generate_summaries(
                raw_host_data, 
                request.get('summary_types', ['overview', 'services', 'infrastructure'])
            )
            analysis_method = "ai"
            ai_model_used = summarizer.last_ai_model_used
        except Exception as ai_error:
            logger.warning(f"AI analysis failed for {host_ip}, falling back to rule-based: {ai_error}")
            # Fallback to rule-based analysis
            summaries = await summarizer.generate_rule_based_summaries(
                normalized_host_data,
                request.get('summary_types', ['overview', 'services', 'infrastructure'])
            )
            analysis_method = "rule_based"
            ai_model_used = None
        
        return SummaryResponse(
            host_ip=host_ip,
            timestamp=datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            summaries=summaries,
            processing_time_ms=summarizer.last_processing_time,
            analysis_method=analysis_method,
            ai_model_used=ai_model_used
        )
        
    except Exception as e:
        logger.error(f"Individual host analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Individual host analysis failed: {str(e)}")

@app.get("/api/summary-types")
async def get_summary_types():
    """Get available summary types and their descriptions"""
    return {
        "summary_types": [
            {
                "type": "executive",
                "description": "High-level risk assessment and business impact analysis",
                "focus": "Business stakeholders, risk management"
            },
            {
                "type": "technical",
                "description": "Detailed service analysis and configuration review",
                "focus": "Technical teams, system administrators"
            },
            {
                "type": "security",
                "description": "Vulnerability prioritization and remediation recommendations",
                "focus": "Security teams, incident response"
            }
        ]
    }

@app.post("/api/export")
async def export_summary(
    summary_data: SummaryResponse,
    format: str = "pdf"
):
    """
    Export summary data in various formats (PDF, JSON, TXT)
    """
    try:
        if format.lower() == "pdf":
            content = export_service.export_to_pdf(summary_data)
            return FileResponse(
                io.BytesIO(content),
                media_type="application/pdf",
                filename=f"censys_analysis_{summary_data.host_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
        elif format.lower() == "json":
            content = export_service.export_to_json(summary_data)
            return JSONResponse(
                content=json.loads(content),
                headers={"Content-Disposition": f"attachment; filename=censys_analysis_{summary_data.host_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
            )
        elif format.lower() == "txt":
            content = export_service.export_to_txt(summary_data)
            return Response(
                content=content,
                media_type="text/plain",
                headers={"Content-Disposition": f"attachment; filename=censys_analysis_{summary_data.host_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"}
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format. Use 'pdf', 'json', or 'txt'")
            
    except Exception as e:
        logger.error(f"Error exporting summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
