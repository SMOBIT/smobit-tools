const express = require('express');
const pdf = require('pdf-parse');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const forge = require('node-forge');

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
      parseSmime: 'POST /parse/smime - Parse S/MIME encrypted/signed messages (auth required)',
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
      },
      {
        name: 'S/MIME Parser',
        endpoint: '/parse/smime',
        method: 'POST',
        description: 'Parse and decrypt S/MIME encrypted/signed messages',
        authentication: 'Required (X-API-Key header)',
        rateLimit: '100 requests per 15 minutes',
        maxFileSize: '10MB',
        parameters: {
          smime: 'S/MIME message content (required)',
          privateKey: 'PEM encoded private key for decryption (optional)',
          password: 'Password for encrypted private key (optional)'
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

// S/MIME Parser Endpoint (mit API-Key Authentifizierung)
app.post('/parse/smime', authenticateApiKey, async (req, res) => {
  try {
    const { smime, privateKey, password } = req.body;

    if (!smime) {
      return res.status(400).json({
        error: 'S/MIME content is required',
        message: 'Please provide the smime parameter with the S/MIME message content'
      });
    }

    // S/MIME Nachricht als PEM verarbeiten
    let p7;
    try {
      // PKCS7 Nachricht aus PEM oder raw format parsen
      if (smime.includes('-----BEGIN')) {
        const msg = forge.pki.messageFromPem(smime);
        p7 = forge.pkcs7.messageFromPem(smime);
      } else {
        // Versuche als base64 zu dekodieren
        const der = forge.util.decode64(smime);
        const asn1 = forge.asn1.fromDer(der);
        p7 = forge.pkcs7.messageFromAsn1(asn1);
      }
    } catch (e) {
      return res.status(400).json({
        error: 'Invalid S/MIME format',
        message: 'Could not parse S/MIME message. Please provide valid PKCS#7/S/MIME format.',
        details: e.message
      });
    }

    const result = {
      success: true,
      type: null,
      content: null,
      certificates: [],
      signers: [],
      recipients: []
    };

    // Prüfe ob signiert
    if (p7.type === forge.pki.oids.signedData) {
      result.type = 'signed';

      // Extrahiere Zertifikate
      if (p7.certificates && p7.certificates.length > 0) {
        result.certificates = p7.certificates.map(cert => ({
          subject: cert.subject.attributes.map(attr => ({
            name: attr.name,
            value: attr.value
          })),
          issuer: cert.issuer.attributes.map(attr => ({
            name: attr.name,
            value: attr.value
          })),
          serialNumber: cert.serialNumber,
          validity: {
            notBefore: cert.validity.notBefore,
            notAfter: cert.validity.notAfter
          }
        }));
      }

      // Extrahiere Signer-Informationen
      if (p7.rawCapture && p7.rawCapture.content) {
        result.content = p7.rawCapture.content.toString('utf8');
      }
    }

    // Prüfe ob verschlüsselt (envelopedData)
    if (p7.type === forge.pki.oids.envelopedData) {
      result.type = 'encrypted';

      if (!privateKey) {
        return res.status(400).json({
          error: 'Private key required',
          message: 'This S/MIME message is encrypted. Please provide a privateKey parameter to decrypt it.'
        });
      }

      try {
        // Private Key laden
        let pkey;
        if (password) {
          pkey = forge.pki.decryptRsaPrivateKey(privateKey, password);
        } else {
          pkey = forge.pki.privateKeyFromPem(privateKey);
        }

        if (!pkey) {
          return res.status(400).json({
            error: 'Invalid private key',
            message: 'Could not load private key. Check format and password.'
          });
        }

        // Entschlüsseln
        p7.decrypt(p7.recipients[0], pkey);
        result.content = p7.content.toString('utf8');

        // Empfänger-Informationen
        result.recipients = p7.recipients.map(recipient => ({
          serialNumber: recipient.serialNumber,
          issuer: recipient.issuer
        }));

      } catch (e) {
        return res.status(400).json({
          error: 'Decryption failed',
          message: 'Could not decrypt S/MIME message. Check if the private key matches the recipient.',
          details: e.message
        });
      }
    }

    // Signiert UND verschlüsselt (erst entschlüsseln, dann verifizieren)
    if (p7.type === forge.pki.oids.envelopedData && result.content) {
      try {
        const innerP7 = forge.pkcs7.messageFromPem(result.content);
        if (innerP7.type === forge.pki.oids.signedData) {
          result.type = 'encrypted-and-signed';
          if (innerP7.rawCapture && innerP7.rawCapture.content) {
            result.content = innerP7.rawCapture.content.toString('utf8');
          }
        }
      } catch (e) {
        // Kein inneres signiertes Format, verwende bereits entschlüsselten Content
      }
    }

    if (!result.content) {
      return res.status(400).json({
        error: 'Could not extract content',
        message: 'S/MIME message type not supported or content could not be extracted'
      });
    }

    res.json(result);

  } catch (error) {
    console.error('S/MIME parsing error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to parse S/MIME message',
      message: error.message
    });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: ['/', '/health', '/tools', '/parse/pdf', '/parse/smime']
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

