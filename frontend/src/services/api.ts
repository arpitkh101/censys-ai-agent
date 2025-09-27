import axios, { AxiosResponse } from 'axios';
import { SummaryResponse, HostData, MultiHostOverviewResponse } from '../types';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://backend:8000',
  timeout: 30000, // 30 seconds timeout for AI processing
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for logging
api.interceptors.request.use(
  (config) => {
    console.log(`Making ${config.method?.toUpperCase()} request to ${config.url}`);
    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('Response error:', error);
    
    if (error.response?.data?.detail) {
      throw new Error(error.response.data.detail);
    } else if (error.message) {
      throw new Error(error.message);
    } else {
      throw new Error('An unexpected error occurred');
    }
  }
);

/**
 * Summarize host data directly
 */
export const summarizeHostData = async (
  hostData: HostData,
  summaryTypes: string[] = ['overview', 'services', 'infrastructure']
): Promise<SummaryResponse> => {
  try {
    // Wrap single host data in the expected format for the new endpoint
    const requestData = {
      hosts: [hostData],
      metadata: {
        description: "Single host analysis",
        created_at: new Date().toISOString()
      }
    };
    
    const response: AxiosResponse<any> = await api.post('/api/analyze-hosts', requestData);
    
    // The new endpoint returns MultiHostOverviewResponse, we need to extract the first host
    if (response.data.hosts_overview && response.data.hosts_overview.length > 0) {
      const firstHost = response.data.hosts_overview[0];
      // Convert to SummaryResponse format for compatibility
      return {
        host_ip: firstHost.ip,
        timestamp: response.data.timestamp,
        summaries: {
          overview: {
            ip: firstHost.ip,
            location: firstHost.location || 'Unknown',
            hostname: firstHost.hostname || null,
            risk_level: firstHost.risk_level || 'UNKNOWN',
            confidence: 'medium',
            key_findings: [`Host ${firstHost.ip} analyzed with ${firstHost.total_services} services`],
            immediate_action: 'Review security findings'
          },
          services: {
            services: []
          },
          infrastructure: {
            hosting_provider: firstHost.as_name || 'Unknown',
            geographic_notes: firstHost.location || 'Unknown',
            certificate_issues: [],
            network_behavior: 'Analysis completed'
          }
        },
        processing_time_ms: response.data.processing_time_ms,
        analysis_method: response.data.analysis_method,
        ai_model_used: response.data.ai_model_used
      };
    } else {
      throw new Error('No host data found in response');
    }
  } catch (error) {
    console.error('Error summarizing host data:', error);
    throw error;
  }
};

/**
 * Upload file and get summary
 */
export const uploadAndSummarize = async (
  file: File,
  summaryTypes: string[] = ['overview', 'services', 'infrastructure']
): Promise<SummaryResponse> => {
  try {
    const formData = new FormData();
    formData.append('file', file);

    const response: AxiosResponse<any> = await api.post(
      '/api/analyze-hosts/upload',
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    );
    
    // The new endpoint returns MultiHostOverviewResponse, we need to extract the first host
    if (response.data.hosts_overview && response.data.hosts_overview.length > 0) {
      const firstHost = response.data.hosts_overview[0];
      // Convert to SummaryResponse format for compatibility
      return {
        host_ip: firstHost.ip,
        timestamp: response.data.timestamp,
        summaries: {
          overview: {
            ip: firstHost.ip,
            location: firstHost.location || 'Unknown',
            hostname: firstHost.hostname || null,
            risk_level: firstHost.risk_level || 'UNKNOWN',
            confidence: 'medium',
            key_findings: [`Host ${firstHost.ip} analyzed with ${firstHost.total_services} services`],
            immediate_action: 'Review security findings'
          },
          services: {
            services: []
          },
          infrastructure: {
            hosting_provider: firstHost.as_name || 'Unknown',
            geographic_notes: firstHost.location || 'Unknown',
            certificate_issues: [],
            network_behavior: 'Analysis completed'
          }
        },
        processing_time_ms: response.data.processing_time_ms,
        analysis_method: response.data.analysis_method,
        ai_model_used: response.data.ai_model_used
      };
    } else {
      throw new Error('No host data found in response');
    }
  } catch (error) {
    console.error('Error uploading and summarizing file:', error);
    throw error;
  }
};

/**
 * Summarize multiple hosts in bulk
 */
export const summarizeBulkHosts = async (
  hostsData: HostData[],
  summaryTypes: string[] = ['overview', 'services', 'infrastructure']
): Promise<{ results: SummaryResponse[]; total_hosts: number; processed_hosts: number }> => {
  try {
    const response = await api.post('/api/summarize/bulk', {
      hosts_data: hostsData,
      summary_types: summaryTypes,
    });
    return response.data;
  } catch (error) {
    console.error('Error summarizing bulk hosts:', error);
    throw error;
  }
};

/**
 * Analyze hosts from pasted JSON data - returns full multi-host overview
 */
export const analyzeHostsFromPaste = async (
  hostData: any
): Promise<MultiHostOverviewResponse> => {
  try {
    const response: AxiosResponse<MultiHostOverviewResponse> = await api.post('/api/analyze-hosts/paste', hostData);
    return response.data;
  } catch (error) {
    console.error('Error analyzing hosts from paste:', error);
    throw error;
  }
};

/**
 * Analyze hosts from uploaded file - returns full multi-host overview
 */
export const analyzeHostsFromFile = async (
  file: File
): Promise<MultiHostOverviewResponse> => {
  try {
    const formData = new FormData();
    formData.append('file', file);

    const response: AxiosResponse<MultiHostOverviewResponse> = await api.post(
      '/api/analyze-hosts/upload',
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error analyzing hosts from file:', error);
    throw error;
  }
};

/**
 * Get detailed summary for a specific host
 */
export const getHostDetailedSummary = async (
  hostData: any
): Promise<SummaryResponse> => {
  try {
    const response: AxiosResponse<SummaryResponse> = await api.post('/api/summarize_host', {
      host_data: hostData,
      summary_types: ['overview', 'services', 'infrastructure']
    });
    return response.data;
  } catch (error) {
    console.error('Error getting detailed host summary:', error);
    throw error;
  }
};

/**
 * Analyze individual host with new AI structure
 */
export const analyzeIndividualHost = async (
  hostIp: string,
  hostData: any,
  summaryTypes: string[] = ['overview', 'services', 'infrastructure']
): Promise<SummaryResponse> => {
  try {
    const response: AxiosResponse<SummaryResponse> = await api.post(`/api/analyze-hosts/individual/${hostIp}`, {
      host_data: hostData,
      summary_types: summaryTypes
    });
    return response.data;
  } catch (error) {
    console.error('Error analyzing individual host:', error);
    throw error;
  }
};

/**
 * Get available summary types
 */
export const getSummaryTypes = async (): Promise<{
  summary_types: Array<{
    type: string;
    description: string;
    focus: string;
  }>;
}> => {
  try {
    const response = await api.get('/api/summary-types');
    return response.data;
  } catch (error) {
    console.error('Error getting summary types:', error);
    throw error;
  }
};

/**
 * Health check
 */
export const healthCheck = async (): Promise<{
  status: string;
  timestamp: string;
  service: string;
}> => {
  try {
    const response = await api.get('/health');
    return response.data;
  } catch (error) {
    console.error('Error checking health:', error);
    throw error;
  }
};

/**
 * Export summary data
 */
export const exportSummary = async (
  summaryData: SummaryResponse,
  format: 'pdf' | 'json' | 'txt'
): Promise<Blob> => {
  try {
    const response = await api.post(
      '/api/export',
      { summary_data: summaryData, format },
      { responseType: 'blob' }
    );
    return response.data;
  } catch (error) {
    console.error('Error exporting summary:', error);
    throw error;
  }
};

export default api;
