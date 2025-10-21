const express = require('express');
const pdf = require('pdf-parse');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '50mb' }));

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Root Endpoint mit API-Übersicht
app.get('/', (req, res) => {
  res.json({
    name: 'SMOBIT Tools API',
    version: '1.0.0',
    endpoints: {
      health: 'GET /health - Health check',
      parsePdf: 'POST /parse/pdf - Parse PDF from URL or base64',
      tools: 'GET /tools - List available tools'
    }
  });
});

// Liste aller verfügbaren Tools
app.get('/tools', (req, res) => {
  res.json({
    tools: [
      {
        name: 'PDF Parser',
        endpoint: '/parse/pdf',
        method: 'POST',
        description: 'Parse PDF files from URL or base64 data',
        parameters: {
          url: 'URL to PDF file (optional)',
          base64: 'Base64 encoded PDF data (optional)'
        }
      }
    ]
  });
});

// PDF Parser Endpoint
app.post('/parse/pdf', async (req, res) => {
  try {
    const { url, base64 } = req.body;

    if (!url && !base64) {
      return res.status(400).json({
        error: 'Either url or base64 parameter is required'
      });
    }

    let dataBuffer;

    // PDF von URL laden
    if (url) {
      const response = await axios.get(url, {
        responseType: 'arraybuffer',
        timeout: 30000
      });
      dataBuffer = Buffer.from(response.data);
    }
    // PDF von Base64 laden
    else if (base64) {
      dataBuffer = Buffer.from(base64, 'base64');
    }

    // PDF parsen
    const data = await pdf(dataBuffer);

    res.json({
      success: true,
      text: data.text,
      pages: data.numpages,
      info: data.info,
      metadata: data.metadata,
      version: data.version
    });

  } catch (error) {
    console.error('PDF parsing error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to parse PDF',
      message: error.message
    });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: ['/', '/health', '/tools', '/parse/pdf']
  });
});

// Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SMOBIT Tools Server läuft auf Port ${PORT}`);
  console.log(`📝 API Dokumentation: http://localhost:${PORT}/`);
  console.log(`❤️  Health Check: http://localhost:${PORT}/health`);
});

