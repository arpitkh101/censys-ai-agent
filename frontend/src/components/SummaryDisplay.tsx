import React, { useState } from 'react';
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
} from '@mui/material';
import {
  ExpandMore,
  ExpandLess,
  Download,
  Security,
  Business,
  Build,
  Warning,
  Info,
  Error as ErrorIcon,
  GetApp,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { SummaryResponse, SummaryType } from '../types';

interface SummaryDisplayProps {
  summaryData: SummaryResponse;
  onExport: (format: string) => void;
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

const SummaryDisplay: React.FC<SummaryDisplayProps> = ({
  summaryData,
  onExport,
}) => {
  const [expandedCards, setExpandedCards] = useState<Set<SummaryType>>(
    new Set(['overview' as SummaryType])
  );

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

  const renderOverviewSummary = (summary: any) => (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Grid container spacing={2} alignItems="center" sx={{ mb: 2 }}>
          <Grid item xs={12} sm={6}>
            <Stack direction="row" spacing={2} alignItems="center">
              <Typography variant="h6">Risk Level:</Typography>
              <RiskChip
                label={summary.risk_level}
                risklevel={summary.risk_level}
                size="medium"
              />
            </Stack>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Stack direction="row" spacing={2} alignItems="center">
              <Typography variant="h6">Confidence:</Typography>
              <Chip 
                label={summary.confidence} 
                color={summary.confidence === 'high' ? 'success' : summary.confidence === 'medium' ? 'warning' : 'error'}
                variant="outlined"
              />
            </Stack>
          </Grid>
        </Grid>
        
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="body1">
            <strong>Immediate Action:</strong> {summary.immediate_action}
          </Typography>
        </Alert>

        {summary.threat_context && (
          <Alert severity="info" sx={{ mb: 2 }} icon={<Security />}>
            <Typography variant="body1">
              <strong>Threat Context:</strong> {summary.threat_context}
            </Typography>
          </Alert>
        )}
      </Box>

      <Grid container spacing={2}>
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
    </Box>
  );

  const renderServicesSummary = (summary: any) => (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
        Service Analysis ({summary.services.length} services found)
      </Typography>
      
      {summary.services.map((service: any, index: number) => (
        <Card key={index} sx={{ mb: 2, border: '1px solid', borderColor: 'divider' }}>
          <CardContent>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="h6" gutterBottom>
                  Port {service.port} - {service.protocol}
                </Typography>
                <Stack spacing={1}>
                  <Chip 
                    label={service.service_type} 
                    color="primary" 
                    variant="outlined" 
                    size="small"
                  />
                  <Chip 
                    label={service.security_status} 
                    color={
                      service.security_status === 'vulnerable' ? 'error' :
                      service.security_status === 'misconfigured' ? 'warning' :
                      service.security_status === 'suspicious' ? 'warning' : 'success'
                    }
                    variant="outlined" 
                    size="small"
                  />
                </Stack>
              </Grid>
              
              <Grid item xs={12} sm={6}>
                {service.software && (
                  <Typography variant="body2" color="text.secondary">
                    <strong>Software:</strong> {service.software}
                  </Typography>
                )}
                {service.banner && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    <strong>Banner:</strong> {service.banner}
                  </Typography>
                )}
              </Grid>
              
              {service.critical_issues.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    Critical Issues:
                  </Typography>
                  <List dense>
                    {service.critical_issues.map((issue: string, issueIndex: number) => (
                      <ListItem key={issueIndex} sx={{ py: 0 }}>
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
                <Typography variant="subtitle2" gutterBottom sx={{ mt: 1 }}>
                  Recommendations:
                </Typography>
                <Stack spacing={1}>
                  {service.recommendations.map((rec: any, index: number) => (
                    <Alert 
                      key={index}
                      severity={rec.priority === 'HIGH' ? 'error' : rec.priority === 'MEDIUM' ? 'warning' : 'info'}
                      sx={{ py: 0.5 }}
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
      ))}
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
        return renderServicesSummary(summary);
      case 'infrastructure':
        return renderInfrastructureSummary(summary);
      default:
        return <Typography>Summary content not available</Typography>;
    }
  };

  return (
    <Paper elevation={2} sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Analysis Results
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Host: {summaryData.host_ip} • Processed: {new Date(summaryData.timestamp).toLocaleString()}
            {summaryData.processing_time_ms && (
              <span> • Processing time: {summaryData.processing_time_ms}ms</span>
            )}
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            startIcon={<GetApp />}
            onClick={() => onExport('pdf')}
          >
            PDF
          </Button>
          <Button
            variant="outlined"
            startIcon={<Download />}
            onClick={() => onExport('json')}
          >
            JSON
          </Button>
          <Button
            variant="outlined"
            startIcon={<Download />}
            onClick={() => onExport('txt')}
          >
            TXT
          </Button>
        </Stack>
      </Box>

      <Divider sx={{ mb: 3 }} />

      {Object.entries(summaryData.summaries).map(([type, summary]) => {
        const summaryType = type as SummaryType;
        const isExpanded = expandedCards.has(summaryType);

        return (
          <SummaryCard key={type} elevation={1}>
            <CardHeader
              avatar={getSummaryIcon(summaryType)}
              title={getSummaryTitle(summaryType)}
              subheader={getSummaryDescription(summaryType)}
              action={
                <IconButton onClick={() => toggleCard(summaryType)}>
                  {isExpanded ? <ExpandLess /> : <ExpandMore />}
                </IconButton>
              }
            />
            <Collapse in={isExpanded} timeout="auto" unmountOnExit>
              <CardContent>
                {renderSummaryContent(summaryType, summary)}
              </CardContent>
            </Collapse>
          </SummaryCard>
        );
      })}
    </Paper>
  );
};

export default SummaryDisplay;
