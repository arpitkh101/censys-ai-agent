import React, { useState, useCallback } from 'react';
import {
  ThemeProvider,
  createTheme,
  CssBaseline,
  Container,
  Typography,
  Box,
  AppBar,
  Toolbar,
  Paper,
  Alert,
  Snackbar
} from '@mui/material';
import { styled } from '@mui/material/styles';

import FileUpload from './components/FileUpload';
import SummaryDisplay from './components/SummaryDisplay';
import HostOverviewGrid from './components/HostOverviewGrid';
import HostDetailPage from './components/HostDetailPage';
import { SummaryResponse, MultiHostOverviewResponse } from './types';
import { analyzeHostsFromPaste, analyzeHostsFromFile, getHostDetailedSummary } from './services/api';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
      light: '#42a5f5',
      dark: '#1565c0',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontWeight: 700,
      fontSize: '2.5rem',
    },
    h2: {
      fontWeight: 600,
      fontSize: '2rem',
    },
    h3: {
      fontWeight: 600,
      fontSize: '1.5rem',
    },
  },
  shape: {
    borderRadius: 12,
  },
});

const StyledContainer = styled(Container)(({ theme }) => ({
  paddingTop: theme.spacing(4),
  paddingBottom: theme.spacing(4),
}));

const HeaderPaper = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(3),
  marginBottom: theme.spacing(3),
  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
  color: 'white',
}));

const App: React.FC = () => {
  const [summaryData, setSummaryData] = useState<SummaryResponse | null>(null);
  const [overviewData, setOverviewData] = useState<MultiHostOverviewResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'overview' | 'detail' | 'host-detail'>('overview');
  const [selectedHostData, setSelectedHostData] = useState<any>(null);

  const handleFileUpload = useCallback(async (file: File) => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    setSummaryData(null);
    setOverviewData(null);

    try {
      const result = await analyzeHostsFromFile(file);
      setOverviewData(result);
      setViewMode('overview');
      setSuccessMessage(`Successfully analyzed ${result.total_hosts} hosts!`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during analysis');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleDirectInput = useCallback(async (hostData: any) => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    setSummaryData(null);
    setOverviewData(null);

    try {
      // Check if the data has the expected structure for the new endpoint
      if (hostData.hosts && Array.isArray(hostData.hosts)) {
        // Data already has the correct structure
        const result = await analyzeHostsFromPaste(hostData);
        setOverviewData(result);
        setViewMode('overview');
        setSuccessMessage(`Successfully analyzed ${result.total_hosts} hosts!`);
      } else if (hostData.ip) {
        // Single host data, wrap it in the expected format
        const wrappedData = {
          hosts: [hostData],
          metadata: {
            description: "Single host analysis from paste",
            created_at: new Date().toISOString()
          }
        };
        const result = await analyzeHostsFromPaste(wrappedData);
        setOverviewData(result);
        setViewMode('overview');
        setSuccessMessage(`Successfully analyzed ${result.total_hosts} hosts!`);
      } else {
        throw new Error('Invalid data format. Expected host data with "ip" field or "hosts" array.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during analysis');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleHostSelect = useCallback((hostData: any) => {
    setSelectedHostData(hostData);
    setViewMode('host-detail');
  }, []);

  const handleBackToOverview = useCallback(() => {
    setViewMode('overview');
    setSelectedHostData(null);
    setSummaryData(null);
  }, []);

  const handleCloseError = () => setError(null);
  const handleCloseSuccess = () => setSuccessMessage(null);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AppBar position="static" elevation={0}>
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            🎯 Censys AI Agent
          </Typography>
          <Typography variant="body2" sx={{ opacity: 0.8 }}>
            Intelligent Host Data Summarization
          </Typography>
        </Toolbar>
      </AppBar>

      <StyledContainer maxWidth="xl">
        <HeaderPaper elevation={3}>
          <Typography variant="h1" gutterBottom>
            Censys AI Agent
          </Typography>
          <Typography variant="h5" sx={{ opacity: 0.9, fontWeight: 400 }}>
            Transform complex internet host data into actionable intelligence
          </Typography>
          <Typography variant="body1" sx={{ mt: 2, opacity: 0.8 }}>
            Upload Censys host data and receive intelligent summaries with executive insights, 
            technical analysis, and security recommendations powered by advanced AI.
          </Typography>
        </HeaderPaper>

        {viewMode === 'host-detail' && selectedHostData ? (
          <HostDetailPage
            hostData={selectedHostData}
            onBack={handleBackToOverview}
          />
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <FileUpload
              onFileUpload={handleFileUpload}
              onDirectInput={handleDirectInput}
              loading={loading}
            />

            {overviewData && viewMode === 'overview' && (
              <HostOverviewGrid
                overviewData={overviewData}
                onHostSelect={handleHostSelect}
              />
            )}

            {summaryData && viewMode === 'detail' && (
              <SummaryDisplay
                summaryData={summaryData}
                onExport={(format: string) => {
                  // Export functionality will be implemented
                  console.log(`Exporting as ${format}`);
                }}
              />
            )}
          </Box>
        )}

        <Snackbar
          open={!!error}
          autoHideDuration={6000}
          onClose={handleCloseError}
          anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        >
          <Alert onClose={handleCloseError} severity="error" sx={{ width: '100%' }}>
            {error}
          </Alert>
        </Snackbar>

        <Snackbar
          open={!!successMessage}
          autoHideDuration={4000}
          onClose={handleCloseSuccess}
          anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        >
          <Alert onClose={handleCloseSuccess} severity="success" sx={{ width: '100%' }}>
            {successMessage}
          </Alert>
        </Snackbar>
      </StyledContainer>
    </ThemeProvider>
  );
};

export default App;
