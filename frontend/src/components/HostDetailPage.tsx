import React, { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  Stack,
  IconButton,
  Collapse,
  Divider,
  Alert,
  Grid,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Badge,
  Tabs,
  Tab,
  Drawer,
  AppBar,
  Toolbar,
} from '@mui/material';
import {
  ExpandMore,
  ExpandLess,
  Download,
  Security,
  Business,
  Build,
  Warning,
  CheckCircle,
  Info,
  Error as ErrorIcon,
  GetApp,
  ArrowBack,
  NetworkCheck,
  Computer,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { SummaryResponse, SummaryType, ServiceDetail } from '../types';
import { analyzeIndividualHost } from '../services/api';

interface HostDetailPageProps {
  hostData: any;
  onBack: () => void;
}

const SummaryCard = styled(Card)(({ theme }) => ({
  marginBottom: theme.spacing(2),
  transition: 'all 0.3s ease',
  '&:hover': {
    boxShadow: theme.shadows[8],
  },
}));

const RiskChip = styled(Chip)<{ risklevel: string }>(({ theme, risklevel }) => {
  const getColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return theme.palette.error.main;
      case 'high':
        return theme.palette.warning.main;
      case 'medium':
        return theme.palette.info.main;
      case 'low':
        return theme.palette.success.main;
      default:
        return theme.palette.grey[500];
    }
  };

  return {
    backgroundColor: getColor(risklevel),
    color: 'white',
    fontWeight: 'bold',
  };
});

const ServiceCard = styled(Card)(({ theme }) => ({
  marginBottom: theme.spacing(1),
  cursor: 'pointer',
  transition: 'all 0.2s ease',
  '&:hover': {
    boxShadow: theme.shadows[4],
    transform: 'translateY(-1px)',
  },
  '&.selected': {
    border: `2px solid ${theme.palette.primary.main}`,
    backgroundColor: theme.palette.primary.light + '10',
  },
}));

const HostDetailPage: React.FC<HostDetailPageProps> = ({ hostData, onBack }) => {
  const [summaryData, setSummaryData] = useState<SummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedCards, setExpandedCards] = useState<Set<SummaryType>>(
    new Set(['overview' as SummaryType])
  );
  const [selectedTab, setSelectedTab] = useState(0);
  const [selectedService, setSelectedService] = useState<ServiceDetail | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    if (hostData) {
      performAnalysis();
    }
  }, [hostData]);

  const performAnalysis = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const result = await analyzeIndividualHost(
        hostData.ip,
        hostData,
        ['overview', 'services', 'infrastructure']
      );
      setSummaryData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const toggleCard = (type: SummaryType) => {
    const newExpanded = new Set(expandedCards);
    if (newExpanded.has(type)) {
      newExpanded.delete(type);
    } else {
      newExpanded.add(type);
    }
    setExpandedCards(newExpanded);
  };

  const getSummaryIcon = (type: SummaryType) => {
    switch (type) {
      case 'overview':
        return <Business />;
      case 'services':
        return <Build />;
      case 'infrastructure':
        return <Security />;
      default:
        return <Info />;
    }
  };

  const getSummaryTitle = (type: SummaryType) => {
    switch (type) {
      case 'overview':
        return 'Host Overview';
      case 'services':
        return 'Service Analysis';
      case 'infrastructure':
        return 'Infrastructure Analysis';
      default:
        return 'Summary';
    }
  };

  const getSummaryDescription = (type: SummaryType) => {
    switch (type) {
      case 'overview':
        return 'Host summary with risk assessment and key findings';
      case 'services':
        return 'Detailed analysis of each service and security status';
      case 'infrastructure':
        return 'Infrastructure details and network behavior analysis';
      default:
        return 'Summary analysis';
    }
  };

  const handleServiceClick = (service: ServiceDetail) => {
    setSelectedService(service);
    setDrawerOpen(true);
  };

  const getServiceRiskColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'vulnerable':
        return 'error';
      case 'misconfigured':
      case 'suspicious':
        return 'warning';
      case 'secured':
        return 'success';
      default:
        return 'default';
    }
  };

  const renderOverviewSummary = (summary: any) => (
    <Box>
      {/* Top Section: Host Info (left) + Key Findings (right) */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Typography variant="h6" gutterBottom>
            Host Information
          </Typography>
          <Stack spacing={1}>
            <Typography><strong>IP:</strong> {summary.ip}</Typography>
            <Typography><strong>Location:</strong> {summary.location}</Typography>
            {summary.hostname && (
              <Typography><strong>Hostname:</strong> {summary.hostname}</Typography>
            )}
            <Box sx={{ mt: 2 }}>
              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="body2"><strong>Risk Level:</strong></Typography>
                <RiskChip
                  label={summary.risk_level}
                  risklevel={summary.risk_level}
                  size="small"
                />
              </Stack>
            </Box>
            <Box>
              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="body2"><strong>Confidence:</strong></Typography>
                <Chip 
                  label={summary.confidence} 
                  color={summary.confidence === 'high' ? 'success' : summary.confidence === 'medium' ? 'warning' : 'error'}
                  variant="outlined"
                  size="small"
                />
              </Stack>
            </Box>
          </Stack>
        </Grid>
        <Grid item xs={12} md={6}>
          <Typography variant="h6" gutterBottom>
            Key Findings
          </Typography>
          <List dense>
            {summary.key_findings.map((finding: string, index: number) => (
              <ListItem key={index}>
                <ListItemIcon>
                  <Info color="primary" />
                </ListItemIcon>
                <ListItemText primary={finding} />
              </ListItem>
            ))}
          </List>
        </Grid>
      </Grid>

      {/* Middle Section: Threat Context (full width) */}
      {summary.threat_context && (
        <Alert severity="info" sx={{ mb: 3 }} icon={<Security />}>
          <Typography variant="body1">
            <strong>Threat Context:</strong> {summary.threat_context}
          </Typography>
        </Alert>
      )}

      {/* Bottom Section: Immediate Action (full width) */}
      <Alert severity="warning">
        <Typography variant="body1">
          <strong>Immediate Action:</strong> {summary.immediate_action}
        </Typography>
      </Alert>
    </Box>
  );

  const renderServicesList = (summary: any) => (
    <Box sx={{ display: 'flex', height: '100%' }}>
      {/* Services List - Left 1/4 */}
      <Box sx={{ width: '25%', pr: 2 }}>
        <Typography variant="h6" gutterBottom>
          Services ({summary.services.length})
        </Typography>
        <Box sx={{ maxHeight: '70vh', overflowY: 'auto' }}>
          {summary.services.map((service: ServiceDetail, index: number) => (
            <ServiceCard
              key={index}
              elevation={1}
              onClick={() => handleServiceClick(service)}
              className={selectedService?.port === service.port ? 'selected' : ''}
            >
              <CardContent sx={{ p: 2 }}>
                <Stack spacing={1}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="h6">
                      Port {service.port}
                    </Typography>
                    <Chip
                      label={service.security_status}
                      color={getServiceRiskColor(service.security_status) as any}
                      size="small"
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {service.protocol} • {service.service_type}
                  </Typography>
                  {service.software && (
                    <Typography variant="body2" color="text.secondary">
                      {service.software}
                    </Typography>
                  )}
                  {service.critical_issues.length > 0 && (
                    <Chip
                      label={`${service.critical_issues.length} issues`}
                      color="error"
                      size="small"
                      variant="outlined"
                    />
                  )}
                </Stack>
              </CardContent>
            </ServiceCard>
          ))}
        </Box>
      </Box>

      {/* Service Details Panel - Right 3/4 */}
      <Box sx={{ width: '75%', pl: 2 }}>
        {selectedService ? (
          <Card elevation={2}>
            <CardHeader
              title={`Port ${selectedService.port} - ${selectedService.protocol}`}
              subheader={selectedService.service_type}
              avatar={<NetworkCheck />}
              action={
                <Chip
                  label={selectedService.security_status}
                  color={getServiceRiskColor(selectedService.security_status) as any}
                />
              }
            />
            <CardContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>
                    Service Details
                  </Typography>
                  <Stack spacing={1}>
                    {selectedService.software && (
                      <Typography><strong>Software:</strong> {selectedService.software}</Typography>
                    )}
                    {selectedService.banner && (
                      <Typography><strong>Banner:</strong> {selectedService.banner}</Typography>
                    )}
                  </Stack>
                </Grid>
                
                {selectedService.critical_issues.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="h6" gutterBottom>
                      Critical Issues
                    </Typography>
                    <List dense>
                      {selectedService.critical_issues.map((issue: string, index: number) => (
                        <ListItem key={index} sx={{ py: 0 }}>
                          <ListItemIcon>
                            <ErrorIcon color="error" />
                          </ListItemIcon>
                          <ListItemText 
                            primary={issue}
                            primaryTypographyProps={{ variant: 'body2' }}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                )}
                
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>
                    Recommendations
                  </Typography>
                  <Stack spacing={1}>
                    {selectedService.recommendations.map((rec: any, index: number) => (
                      <Alert 
                        key={index}
                        severity={rec.priority === 'HIGH' ? 'error' : rec.priority === 'MEDIUM' ? 'warning' : 'info'}
                        sx={{ mb: 1 }}
                      >
                        <Typography variant="body2">
                          <strong>[{rec.priority}]</strong> {rec.action}
                          {rec.description && (
                            <>
                              <br />
                              <em>{rec.description}</em>
                            </>
                          )}
                        </Typography>
                      </Alert>
                    ))}
                  </Stack>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        ) : (
          <Box sx={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center', 
            height: '100%',
            color: 'text.secondary'
          }}>
            <Typography variant="h6">
              Select a service to view details
            </Typography>
          </Box>
        )}
      </Box>
    </Box>
  );

  const renderInfrastructureSummary = (summary: any) => (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Typography variant="h6" gutterBottom>
            Hosting Information
          </Typography>
          <Stack spacing={2}>
            <Box>
              <Typography variant="subtitle2" color="text.secondary">
                Hosting Provider
              </Typography>
              <Typography variant="body1">
                {summary.hosting_provider}
              </Typography>
            </Box>
            
            {summary.geographic_notes && (
              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Geographic Notes
                </Typography>
                <Alert severity="info" sx={{ mt: 1 }}>
                  <Typography variant="body2">
                    {summary.geographic_notes}
                  </Typography>
                </Alert>
              </Box>
            )}
          </Stack>
        </Grid>

        <Grid item xs={12} md={6}>
          <Typography variant="h6" gutterBottom>
            Network Behavior
          </Typography>
          {summary.network_behavior ? (
            <Alert severity="warning">
              <Typography variant="body2">
                {summary.network_behavior}
              </Typography>
            </Alert>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No unusual network behavior detected
            </Typography>
          )}
        </Grid>

        <Grid item xs={12}>
          <Typography variant="h6" gutterBottom>
            Certificate Issues
          </Typography>
          {summary.certificate_issues.length > 0 ? (
            <List dense>
              {summary.certificate_issues.map((issue: string, index: number) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    <Warning color="warning" />
                  </ListItemIcon>
                  <ListItemText primary={issue} />
                </ListItem>
              ))}
            </List>
          ) : (
            <Alert severity="success">
              <Typography variant="body2">
                No certificate issues detected
              </Typography>
            </Alert>
          )}
        </Grid>
      </Grid>
    </Box>
  );

  const renderSummaryContent = (type: SummaryType, summary: any) => {
    switch (type) {
      case 'overview':
        return renderOverviewSummary(summary);
      case 'services':
        return renderServicesList(summary);
      case 'infrastructure':
        return renderInfrastructureSummary(summary);
      default:
        return <Typography>Summary content not available</Typography>;
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <Typography variant="h6">Analyzing host data...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
        <Button variant="outlined" onClick={onBack}>
          <ArrowBack sx={{ mr: 1 }} />
          Back to Overview
        </Button>
      </Box>
    );
  }

  if (!summaryData) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h6">No analysis data available</Typography>
        <Button variant="outlined" onClick={onBack} sx={{ mt: 2 }}>
          <ArrowBack sx={{ mr: 1 }} />
          Back to Overview
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <AppBar position="static" elevation={0} sx={{ mb: 3 }}>
        <Toolbar>
          <Button
            color="inherit"
            startIcon={<ArrowBack />}
            onClick={onBack}
            sx={{ mr: 2 }}
          >
            Back
          </Button>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Host Analysis: {hostData.ip}
          </Typography>
          <Stack direction="row" spacing={1}>
            <Chip
              label={`${summaryData.analysis_method?.toUpperCase() || 'UNKNOWN'}`}
              color="primary"
              variant="outlined"
              size="small"
            />
            {summaryData.ai_model_used && (
              <Chip
                label={summaryData.ai_model_used}
                color="secondary"
                variant="outlined"
                size="small"
              />
            )}
          </Stack>
        </Toolbar>
      </AppBar>

      {/* Tabs */}
      <Paper elevation={2} sx={{ mb: 3 }}>
        <Tabs
          value={selectedTab}
          onChange={(e, newValue) => setSelectedTab(newValue)}
          variant="fullWidth"
        >
          <Tab label="Overview" icon={<Business />} />
          <Tab label="Services" icon={<Build />} />
          <Tab label="Infrastructure" icon={<Security />} />
        </Tabs>
      </Paper>

      {/* Content */}
      <Paper elevation={2} sx={{ p: 3, minHeight: '60vh' }}>
        {selectedTab === 0 && summaryData.summaries.overview && (
          renderSummaryContent('overview', summaryData.summaries.overview)
        )}
        {selectedTab === 1 && summaryData.summaries.services && (
          renderSummaryContent('services', summaryData.summaries.services)
        )}
        {selectedTab === 2 && summaryData.summaries.infrastructure && (
          renderSummaryContent('infrastructure', summaryData.summaries.infrastructure)
        )}
      </Paper>
    </Box>
  );
};

export default HostDetailPage;
