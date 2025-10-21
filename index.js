const express = require('express');
const pdf = require('pdf-parse');
const axios = require('axios');
const rateLimit = require('express-rate-limit');

const app = express();

// API Key aus Environment Variable (WICHTIG: In Coolify setzen!)
const API_KEY = process.env.API_KEY || 'change-me-in-production';

// Rate Limiting: Max 100 Requests pro 15 Minuten
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minuten
  max: 100, // Max 100 Requests
  message: {
    error: 'Too many requests, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate Limit für API-Endpoints
app.use('/parse/', limiter);

// Body Parser mit Size Limit (10MB)
app.use(express.json({ limit: '10mb' }));

// API-Key Authentifizierung Middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'API-Key required. Please provide X-API-Key header.'
    });
  }

  if (apiKey !== API_KEY) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Invalid API-Key'
    });
  }

  next();
};

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
    security: {
      authentication: 'API-Key required (X-API-Key header)',
      rateLimit: '100 requests per 15 minutes',
      maxFileSize: '10MB'
    },
    endpoints: {
      health: 'GET /health - Health check (no auth required)',
      parsePdf: 'POST /parse/pdf - Parse PDF from URL or base64 (auth required)',
      tools: 'GET /tools - List available tools (no auth required)'
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
        authentication: 'Required (X-API-Key header)',
        rateLimit: '100 requests per 15 minutes',
        maxFileSize: '10MB',
        parameters: {
          url: 'URL to PDF file (optional)',
          base64: 'Base64 encoded PDF data (optional)'
        }
      }
    ]
  });
});

// PDF Parser Endpoint (mit API-Key Authentifizierung)
app.post('/parse/pdf', authenticateApiKey, async (req, res) => {
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
      // URL Validierung
      try {
        const urlObj = new URL(url);
        if (!['http:', 'https:'].includes(urlObj.protocol)) {
          return res.status(400).json({
            error: 'Invalid URL protocol. Only HTTP and HTTPS are allowed.'
          });
        }
      } catch (e) {
        return res.status(400).json({
          error: 'Invalid URL format'
        });
      }

      const response = await axios.get(url, {
        responseType: 'arraybuffer',
        timeout: 30000,
        maxContentLength: 10 * 1024 * 1024, // Max 10MB
        maxBodyLength: 10 * 1024 * 1024
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

