import React, { useCallback, useState } from 'react';
import {
  Paper,
  Typography,
  Box,
  Button,
  LinearProgress,
  Alert,
  Tabs,
  Tab,
  TextField,
  Chip,
  Stack,
  Divider,
} from '@mui/material';
import { useDropzone } from 'react-dropzone';
import {
  CloudUpload,
  Description,
  Code,
  CheckCircle,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';

interface FileUploadProps {
  onFileUpload: (file: File) => void;
  onDirectInput: (data: any) => void;
  loading: boolean;
}

const UploadArea = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(4),
  textAlign: 'center',
  border: `2px dashed ${theme.palette.primary.main}`,
  backgroundColor: theme.palette.background.paper,
  cursor: 'pointer',
  transition: 'all 0.3s ease',
  '&:hover': {
    backgroundColor: theme.palette.primary.light + '10',
    borderColor: theme.palette.primary.dark,
  },
  '&.drag-active': {
    backgroundColor: theme.palette.primary.light + '20',
    borderColor: theme.palette.primary.dark,
    transform: 'scale(1.02)',
  },
}));

const FileUpload: React.FC<FileUploadProps> = ({
  onFileUpload,
  onDirectInput,
  loading,
}) => {
  const [activeTab, setActiveTab] = useState(0);
  const [jsonInput, setJsonInput] = useState('');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  const onDrop = useCallback(
    (acceptedFiles: File[]) => {
      const file = acceptedFiles[0];
      if (file) {
        setUploadedFile(file);
        setJsonError(null);
        onFileUpload(file);
      }
    },
    [onFileUpload]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/json': ['.json'],
    },
    multiple: false,
    disabled: loading,
  });

  const handleDirectSubmit = () => {
    try {
      const data = JSON.parse(jsonInput);
      setJsonError(null);
      onDirectInput(data);
    } catch (error) {
      setJsonError('Invalid JSON format. Please check your input.');
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
    setJsonError(null);
    setUploadedFile(null);
  };

  const exampleJson = `{
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
          "transport_protocol": "udp"
        }
      ]
    }
  ]
}`;

  return (
    <Paper elevation={2} sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Upload Host Data
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Choose how you'd like to provide Censys host data for analysis
      </Typography>

      <Tabs
        value={activeTab}
        onChange={handleTabChange}
        sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}
      >
        <Tab
          icon={<CloudUpload />}
          label="Upload File"
          iconPosition="start"
          disabled={loading}
        />
        <Tab
          icon={<Code />}
          label="Paste JSON"
          iconPosition="start"
          disabled={loading}
        />
      </Tabs>

      {loading && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
            Analyzing host data with AI...
          </Typography>
        </Box>
      )}

      {activeTab === 0 && (
        <Box>
          <UploadArea
            {...getRootProps()}
            className={isDragActive ? 'drag-active' : ''}
            sx={{ mb: 2 }}
          >
            <input {...getInputProps()} />
            <CloudUpload sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              {isDragActive
                ? 'Drop the JSON file here'
                : 'Drag & drop a JSON file here, or click to select'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Supports Censys host data in JSON format
            </Typography>
          </UploadArea>

          {uploadedFile && (
            <Alert
              icon={<CheckCircle />}
              severity="success"
              sx={{ mb: 2 }}
              action={
                <Chip
                  label={uploadedFile.name}
                  size="small"
                  color="primary"
                  variant="outlined"
                />
              }
            >
              File uploaded successfully
            </Alert>
          )}

          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Supported formats:
            </Typography>
            <Stack direction="row" spacing={1} flexWrap="wrap">
              <Chip label="JSON" size="small" color="primary" variant="outlined" />
            </Stack>
          </Box>
        </Box>
      )}

      {activeTab === 1 && (
        <Box>
          <Typography variant="subtitle1" gutterBottom>
            Paste your Censys host data JSON:
          </Typography>
          <TextField
            multiline
            rows={12}
            fullWidth
            value={jsonInput}
            onChange={(e) => {
              setJsonInput(e.target.value);
              setJsonError(null);
            }}
            placeholder={exampleJson}
            variant="outlined"
            sx={{ mb: 2 }}
            disabled={loading}
          />

          {jsonError && (
            <Alert
              icon={<ErrorIcon />}
              severity="error"
              sx={{ mb: 2 }}
            >
              {jsonError}
            </Alert>
          )}

          <Button
            variant="contained"
            onClick={handleDirectSubmit}
            disabled={loading || !jsonInput.trim()}
            startIcon={<Description />}
            size="large"
          >
            Analyze Data
          </Button>

          <Divider sx={{ my: 2 }} />

          <Typography variant="subtitle2" gutterBottom>
            Example JSON structure:
          </Typography>
          <Box
            component="pre"
            sx={{
              backgroundColor: 'grey.100',
              p: 2,
              borderRadius: 1,
              fontSize: '0.875rem',
              overflow: 'auto',
              maxHeight: 200,
            }}
          >
            {exampleJson}
          </Box>
        </Box>
      )}
    </Paper>
  );
};

export default FileUpload;
