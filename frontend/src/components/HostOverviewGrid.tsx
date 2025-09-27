import React, { useState } from 'react';
import {
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  CardHeader,
  Chip,
  Stack,
  Grid,
  Button,
  Badge,
  Alert,
  Divider,
} from '@mui/material';
import {
  Security,
  LocationOn,
  Router,
  Computer,
  Warning,
  CheckCircle,
  Info,
  Error as ErrorIcon,
  Visibility,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';

interface RiskyService {
  port: number;
  protocol: string;
  risk_reason: string;
  vulnerability_count: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
}

interface HostOverview {
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

interface MultiHostOverviewResponse {
  total_hosts: number;
  timestamp: string;
  hosts_overview: HostOverview[];
  processing_time_ms: number;
  analysis_method: string;
  ai_model_used?: string;
  metadata?: any;
}

interface HostOverviewGridProps {
  overviewData: MultiHostOverviewResponse;
  onHostSelect: (hostData: any) => void;
}

const StyledCard = styled(Card)(({ theme }) => ({
  marginBottom: theme.spacing(2),
  transition: 'all 0.3s ease',
  cursor: 'pointer',
  '&:hover': {
    boxShadow: theme.shadows[8],
    transform: 'translateY(-2px)',
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
    minWidth: 80,
  };
});

const HostOverviewGrid: React.FC<HostOverviewGridProps> = ({
  overviewData,
  onHostSelect,
}) => {
  const [selectedHost, setSelectedHost] = useState<string | null>(null);

  const handleHostClick = (host: HostOverview) => {
    setSelectedHost(host.ip);
    if (host.full_host_data) {
      onHostSelect(host.full_host_data);
    }
  };

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel?.toLowerCase()) {
      case 'critical':
        return <ErrorIcon color="error" />;
      case 'high':
        return <Warning color="warning" />;
      case 'medium':
        return <Info color="info" />;
      case 'low':
        return <CheckCircle color="success" />;
      default:
        return <Info color="disabled" />;
    }
  };

  // const getRiskColor = (riskLevel: string) => {
  //   switch (riskLevel?.toLowerCase()) {
  //     case 'critical':
  //       return 'error';
  //     case 'high':
  //       return 'warning';
  //     case 'medium':
  //       return 'info';
  //     case 'low':
  //       return 'success';
  //     default:
  //       return 'default';
  //   }
  // };

  return (
    <Paper elevation={2} sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Host Overview
          </Typography>
          <Typography variant="body1" color="text.secondary">
            {overviewData.total_hosts} hosts analyzed • Processed: {overviewData.timestamp}
            {overviewData.processing_time_ms && (
              <span> • Processing time: {overviewData.processing_time_ms}ms</span>
            )}
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Chip
            label={`${overviewData.analysis_method.toUpperCase()}`}
            color="primary"
            variant="outlined"
          />
          {overviewData.ai_model_used && (
            <Chip
              label={overviewData.ai_model_used}
              color="secondary"
              variant="outlined"
            />
          )}
        </Stack>
      </Box>

      <Divider sx={{ mb: 3 }} />

      <Grid container spacing={3}>
        {overviewData.hosts_overview.map((host) => (
          <Grid item xs={12} md={6} lg={4} key={host.ip}>
            <StyledCard
              elevation={selectedHost === host.ip ? 8 : 2}
              onClick={() => handleHostClick(host)}
              sx={{
                border: selectedHost === host.ip ? 2 : 0,
                borderColor: 'primary.main',
              }}
            >
              <CardHeader
                avatar={getRiskIcon(host.risk_level || 'unknown')}
                title={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="h6" component="span">
                      {host.ip}
                    </Typography>
                    <RiskChip
                      label={host.risk_level || 'UNKNOWN'}
                      risklevel={host.risk_level || 'unknown'}
                      size="small"
                    />
                  </Box>
                }
                subheader={
                  <Box>
                    {host.location && (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                        <LocationOn fontSize="small" color="action" />
                        <Typography variant="body2" color="text.secondary">
                          {host.location}
                        </Typography>
                      </Box>
                    )}
                    {host.hostname && (
                      <Typography variant="body2" color="text.secondary">
                        {host.hostname}
                      </Typography>
                    )}
                  </Box>
                }
              />
              <CardContent>
                <Stack spacing={2}>
                  {/* Network Information */}
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      Network Information
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      {host.asn && (
                        <Chip
                          icon={<Router />}
                          label={`ASN ${host.asn}`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                      {host.country_code && (
                        <Chip
                          label={host.country_code}
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </Stack>
                  </Box>

                  {/* Services */}
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      Services
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      <Chip
                        icon={<Computer />}
                        label={`${host.total_services} services`}
                        size="small"
                        color="primary"
                        variant="outlined"
                      />
                      {host.open_ports.slice(0, 3).map((port) => (
                        <Chip
                          key={port}
                          label={port}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                      {host.open_ports.length > 3 && (
                        <Chip
                          label={`+${host.open_ports.length - 3} more`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </Stack>
                  </Box>

                  {/* Risky Services - Commented out for later use */}
                  {/* {host.risky_services && host.risky_services.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" gutterBottom color="error">
                        ⚠️ Risky Services
                      </Typography>
                      <Stack spacing={1}>
                        {host.risky_services.slice(0, 2).map((service, index) => (
                          <Alert
                            key={index}
                            severity="warning"
                            sx={{ py: 0.5 }}
                            icon={<Security />}
                          >
                            <Typography variant="body2">
                              <strong>Port {service.port} ({service.protocol})</strong>
                              <br />
                              {service.risk_reason}
                            </Typography>
                          </Alert>
                        ))}
                        {host.risky_services.length > 2 && (
                          <Typography variant="caption" color="error">
                            +{host.risky_services.length - 2} more risky services
                          </Typography>
                        )}
                      </Stack>
                    </Box>
                  )} */}

                  {/* Vulnerabilities */}
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      Vulnerabilities
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      <Badge badgeContent={host.critical_vulnerabilities} color="error">
                        <Chip
                          icon={<Security />}
                          label="Critical"
                          size="small"
                          color="error"
                          variant="outlined"
                        />
                      </Badge>
                      <Badge badgeContent={host.high_vulnerabilities} color="warning">
                        <Chip
                          label="High"
                          size="small"
                          color="warning"
                          variant="outlined"
                        />
                      </Badge>
                      <Chip
                        label={`${host.total_vulnerabilities} total`}
                        size="small"
                        variant="outlined"
                      />
                    </Stack>
                  </Box>

                  {/* Protocols */}
                  {host.protocols.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" gutterBottom>
                        Protocols
                      </Typography>
                      <Stack direction="row" spacing={1} flexWrap="wrap">
                        {host.protocols.slice(0, 4).map((protocol) => (
                          <Chip
                            key={protocol}
                            label={protocol}
                            size="small"
                            variant="outlined"
                          />
                        ))}
                        {host.protocols.length > 4 && (
                          <Chip
                            label={`+${host.protocols.length - 4} more`}
                            size="small"
                            variant="outlined"
                          />
                        )}
                      </Stack>
                    </Box>
                  )}
                </Stack>
              </CardContent>
            </StyledCard>
          </Grid>
        ))}
      </Grid>

      {overviewData.metadata && (
        <Box sx={{ mt: 3 }}>
          <Alert severity="info">
            <Typography variant="body2">
              <strong>Dataset Info:</strong> {overviewData.metadata.description || 'No description available'}
            </Typography>
          </Alert>
        </Box>
      )}
    </Paper>
  );
};

export default HostOverviewGrid;
