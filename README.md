# Censys AI Agent: Intelligent Host Data Summarization

🎯 **Transform complex internet host data into actionable intelligence**

The Censys AI Agent is a full-stack application that leverages advanced language models to convert dense technical information from Censys host records into clear, structured summaries. This tool enables rapid threat assessment, asset discovery, and security analysis for cybersecurity professionals.

## 🚀 Key Features

### Intelligent Summarization Engine
- **Multi-Perspective Analysis**: Generate executive, technical, and infrastructure summaries from the same data
- **Threat-Aware Processing**: Automatically identifies and prioritizes active threats, critical vulnerabilities (CVEs), malware indicators, and security misconfigurations
- **Context-Rich Insights**: Translates technical details like CPE values, certificate hashes, and service banners into actionable intelligence

### Advanced Data Processing
- **Hierarchical Data Parsing**: Handles complex nested structures including services, software components, and protocol-specific information
- **Intelligent Extraction**: Focuses on high-value data points including threat indicators, network routing (ASN), DNS records, and software fingerprints
- **Pattern Recognition**: Identifies suspicious service combinations, hosting anomalies, and threat actor infrastructure

### User-Centric Interface
- **Intuitive Input Methods**: Support for JSON upload, direct paste, and file import
- **Interactive Summary Display**: Structured cards with expandable sections for detailed exploration
- **Export Capabilities**: Generate reports in multiple formats (PDF, JSON, structured text)

## 🛠 Technical Architecture

### Backend Stack
- **FastAPI Framework**: High-performance API with automatic documentation
- **Multi-LLM Integration**: OpenAI GPT-4, Anthropic Claude, Google Gemini with intelligent fallbacks
- **Robust Data Validation**: Comprehensive error handling and data sanitization using Pydantic
- **Scalable Processing**: Optimized for both single-host and bulk analysis workflows

### Frontend Stack
- **React + TypeScript**: Modern, type-safe user interface
- **Material-UI**: Responsive design optimized for desktop and mobile experiences
- **Component Architecture**: Modular, reusable UI components
- **State Management**: Efficient handling of complex application state with React hooks

### AI/ML Components
- **Threat-Focused Prompts**: Custom-engineered prompts optimized for cybersecurity threat hunting
- **Structured Intelligence Output**: Consistent JSON-formatted summaries for SIEM integration
- **Confidence Scoring**: Quality assessment for threat intelligence reliability
- **Fallback Mechanisms**: Rule-based analysis when AI services are unavailable

## 🔍 Analysis Categories

### Threat Assessment
- Active threat identification and risk scoring
- Threat actor attribution and campaign correlation
- Immediate action recommendations with timelines
- Confidence levels for intelligence reliability

### Service Analysis
- Detailed port and protocol analysis
- Software inventory with vulnerability correlation
- Attack vector identification for each service  
- Service-specific remediation with priority levels

### Infrastructure Intelligence
- Hosting provider analysis and reputation scoring
- Geographic anomaly detection (ASN vs GeoIP)
- Certificate analysis and trust indicators
- Network behavior patterns and suspicious configurations

## 📋 Prerequisites

### Recommended: Docker Setup
- Docker and Docker Compose
- OpenAI or Anthropic or Gemini API key (optional, falls back to rule-based analysis)

### Alternative: Manual Installation
- Python 3.8+
- Node.js 18+ (recommended: 18.x LTS)
- npm 8+ or yarn
- OpenAI or Anthropic or Gemini API key (optional, falls back to rule-based analysis)

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd data_summ_agent
```

### 2. Docker Setup (Recommended)

#### Quick Start with Docker
```bash
# Set up environment variables
cp backend/env.example backend/.env
# Edit backend/.env with your API keys

# Start the application
docker-compose up --build
```

**That's it!** The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

### 3. Alternative: Manual Installation

If you prefer to run without Docker, follow these steps:

#### Backend Setup
```bash
cd backend

# Install system dependencies
# On Ubuntu/Debian:
sudo apt-get update && sudo apt-get install -y build-essential libssl-dev libffi-dev curl
# On macOS with Homebrew:
# brew install openssl libffi curl
# On Windows: Install Visual Studio Build Tools or use conda/miniconda

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate.bat

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Set up environment variables
cp env.example .env
# Edit .env with your API keys
```

#### Frontend Setup
```bash
cd frontend

# Verify Node.js version (should be 18+)
node --version

# Install dependencies
npm install
```

#### Manual Start
```bash
# Terminal 1 - Backend
cd backend
python run.py

# Terminal 2 - Frontend
cd frontend
npm start
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
# AI Model API Keys (only one needed - choose your preferred provider)
OPENAI_API_KEY=your_openai_api_key_here
# ANTHROPIC_API_KEY=your_anthropic_api_key_here
# GEMINI_API_KEY=your_gemini_api_key_here

# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=True

# CORS Settings
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

### API Keys Setup

**You only need ONE API key** - choose your preferred AI provider:

1. **OpenAI** (Recommended): Get your API key from [OpenAI Platform](https://platform.openai.com/api-keys)
2. **Anthropic**: Get your API key from [Anthropic Console](https://console.anthropic.com/)
3. **Google Gemini**: Get your API key from [Google AI Studio](https://makersuite.google.com/app/apikey)

**Note**: The application works without API keys using rule-based analysis, but AI-powered summaries provide much richer insights. If you provide multiple API keys, the system will use them as fallbacks if the primary one fails.

## 📖 Usage

### 1. Upload Host Data

#### Method 1: File Upload
- Click "Upload File" tab
- Drag and drop a JSON file containing Censys host data
- Or click to browse and select a file

#### Method 2: Direct JSON Input
- Click "Paste JSON" tab
- Paste your Censys host data JSON directly
- Click "Analyze Data"

### 2. View Summaries

The application generates three types of summaries:

- **Overview**: Risk level, key findings, and immediate actions
- **Services**: Service analysis, security status, and recommendations
- **Infrastructure**: Hosting information, network behavior, and certificate issues


## 📊 Data Format

### Supported Input Formats

The application accepts Censys host data in the following format:

```json
{
  "metadata": {
    "description": "Example host data",
    "created_at": "2024-01-15"
  },
  "hosts": [
    {
      "ip": "8.8.8.8",
      "location": {
        "country": "United States",
        "city": "Mountain View"
      },
      "autonomous_system": {
        "asn": 15169,
        "name": "Google LLC"
      },
      "services": [
        {
          "port": 53,
          "protocol": "DNS",
          "transport_protocol": "udp",
          "software": [
            {
              "product": "BIND",
              "version": "9.16.1",
              "vendor": "ISC",
              "confidence": 0.9
            }
          ],
          "vulns": [
            {
              "id": "CVE-2021-25220",
              "severity": "HIGH",
              "kev": false,
              "description": "BIND vulnerability"
            }
          ]
        }
      ]
    }
  ]
}
```

## 🔌 API Reference

### Core Endpoints

#### `POST /api/analyze-hosts`
Generate multi-host overview analysis
```json
{
  "hosts": [/* array of host data */],
  "metadata": {/* optional metadata */}
}
```

#### `POST /api/analyze-hosts/upload`
Upload and process a JSON file
- **Content-Type**: `multipart/form-data`
- **Parameters**: `file`

#### `POST /api/analyze-hosts/individual/{host_ip}`
Analyze individual host with detailed AI summaries
```json
{
  "host_data": {/* single host data */},
  "summary_types": ["overview", "services", "infrastructure"]
}
```

#### `GET /health`
Health check endpoint

### Response Format

```json
{
  "host_ip": "8.8.8.8",
  "timestamp": "2024-01-15T10:30:00Z",
  "processing_time_ms": 2500,
  "summaries": {
    "overview": {
      "ip": "8.8.8.8",
      "location": "Mountain View, United States",
      "risk_level": "MEDIUM",
      "confidence": "high",
      "threat_context": "No immediate threats detected",
      "key_findings": ["Finding 1", "Finding 2"],
      "immediate_action": "Review service configurations"
    },
    "services": { /* service analysis */ },
    "infrastructure": { /* infrastructure analysis */ }
  },
  "analysis_method": "ai",
  "ai_model_used": "gpt-4o-mini"
}
```

## 🧪 Testing

### Manual Testing

1. **Basic Functionality**:
   ```bash
   # Test health endpoint
   curl http://localhost:8000/health
   
   # Test with sample data
   curl -X POST http://localhost:8000/api/analyze-hosts \
     -H "Content-Type: application/json" \
     -d @hosts_test.json
   ```

2. **Frontend Testing**:
   - Upload the provided `hosts_test.json` file
   - Test JSON paste functionality
   - Verify export capabilities
   - Test error handling with invalid data

3. **AI Integration Testing**:
   - Test with and without API keys
   - Verify fallback to rule-based analysis
   - Test different AI models (OpenAI, Anthropic, Gemini)

## 🤖 AI Techniques Implementation

### Prompt Engineering
- **Context-Aware Prompts**: Specialized prompts for cybersecurity threat hunting and analysis
- **Structured Output**: JSON-formatted responses for consistent parsing and integration
- **Risk Prioritization**: Prompts designed to identify and escalate critical security issues

### Model Integration
- **Multi-Model Support**: OpenAI GPT-4, Anthropic Claude, Google Gemini with intelligent failover
- **Output Validation**: AI response quality checks with fallback to alternative models
- **Fallback Mechanisms**: Rule-based analysis engine when AI services are unavailable

### Analysis Techniques
- **Vulnerability Correlation**: CVE data integration with CVSS scoring and KEV catalog matching
- **Threat Intelligence**: Malware signature detection and threat actor infrastructure attribution
- **Geographic Analysis**: ASN vs GeoIP correlation for hosting anomaly detection
- **Confidence Scoring**: AI output quality assessment with reliability metrics

## 🚀 Future Enhancements

### Short-term Improvements
- **Direct Censys API Integration**: Fetch live data instead of manual uploads
- **Export Options**: PDF reports and CSV summaries for stakeholder sharing
- **Advanced Filtering**: Filter results by risk level, location, or service type

### Medium-term Features 
- **Historical Tracking**: Store and compare analysis results over time
- **Custom Templates**: User-defined report formats and analysis focus areas
- **SIEM Integration**: Direct export to Splunk, QRadar, and other security platforms
- **Automated Alerting**: Email/Slack notifications for critical findings

### Advanced Capabilities
- **Cross-host Analysis**: Identify patterns and correlations across multiple hosts
- **Threat Intelligence Feeds**: Integration with commercial threat intel sources
- **Natural Language Queries**: Ask questions like "Show me all critical hosts in US"
- **Team Collaboration**: Shared workspaces and analysis annotations

### Technical Optimizations
- **Response Caching**: Faster results for previously analyzed hosts
- **Database Backend**: Persistent storage for analysis history
- **Performance Tuning**: Optimized processing for large datasets

## 🛡️ Security Considerations

### Data Protection
- **Input Validation**: Comprehensive sanitization of all user inputs
- **API Security**: Rate limiting, authentication, and authorization
- **Data Encryption**: Encryption at rest and in transit
- **Privacy Compliance**: GDPR, CCPA compliance considerations

### Threat Modeling
- **Attack Surface Analysis**: Regular security assessments
- **Vulnerability Management**: Automated dependency scanning
- **Security Headers**: Implementation of security best practices
- **Audit Logging**: Comprehensive logging for security events

## 🆘 Support

- **Documentation**: Check this README and API docs at `/docs`
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Discussions**: Join community discussions for questions and ideas

## 🙏 Acknowledgments

- [Censys](https://censys.com/) for providing comprehensive internet scanning data
- [OpenAI](https://openai.com/), [Anthropic](https://anthropic.com/), and [Google](https://ai.google.dev/) for AI capabilities
- The cybersecurity community for feedback and contributions

---

**Built with ❤️ for the cybersecurity community**

*Transforming complex data into actionable intelligence, one host at a time.*
