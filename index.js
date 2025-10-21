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
      parseSmime: 'POST /parse/smime - Parse S/MIME signed emails - supports complete multipart/signed emails (auth required)',
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
        description: 'Parse S/MIME signed/encrypted messages - supports complete emails (multipart/signed)',
        authentication: 'Required (X-API-Key header)',
        rateLimit: '100 requests per 15 minutes',
        maxFileSize: '10MB',
        parameters: {
          smime: 'S/MIME content - complete email, PEM, Base64, or raw binary (required)',
          privateKey: 'PEM encoded private key for decryption (optional)',
          password: 'Password for encrypted private key (optional)'
        },
        note: 'NEW: Send complete multipart/signed emails! Automatically extracts PKCS#7 signature and email content.'
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

// Helper: Parse multipart/signed email and extract PKCS#7 signature
function extractPKCS7FromEmail(emailContent) {
  // Prüfe ob es eine multipart/signed E-Mail ist
  if (!emailContent.includes('multipart/signed') && !emailContent.includes('application/pkcs7-signature')) {
    return null; // Kein multipart/signed Format
  }

  // Suche nach dem PKCS7-Signatur-Teil
  const lines = emailContent.split('\n');
  let inSignaturePart = false;
  let signatureBase64 = [];
  let extractedContent = [];
  let inContentPart = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Finde den Signatur-Teil
    if (line.includes('Content-Type: application/pkcs7-signature') ||
        line.includes('Content-Type: application/x-pkcs7-signature')) {
      inSignaturePart = true;
      // Überspringe Header bis zur leeren Zeile
      while (i < lines.length && lines[i].trim() !== '') {
        i++;
      }
      continue;
    }

    // Sammle Base64-Daten der Signatur
    if (inSignaturePart && line.trim() !== '' && !line.startsWith('--')) {
      signatureBase64.push(line.trim());
    }

    // Ende der Signatur erreicht
    if (inSignaturePart && line.startsWith('--')) {
      inSignaturePart = false;
    }

    // Extrahiere den eigentlichen Content (text/plain oder text/html)
    if ((line.includes('Content-Type: text/plain') || line.includes('Content-Type: text/html')) && !inContentPart) {
      inContentPart = true;
      // Überspringe Header
      while (i < lines.length && lines[i].trim() !== '') {
        i++;
      }
      continue;
    }

    if (inContentPart && !line.startsWith('--')) {
      extractedContent.push(line);
    }

    if (inContentPart && line.startsWith('--')) {
      inContentPart = false;
    }
  }

  if (signatureBase64.length > 0) {
    return {
      signature: signatureBase64.join(''),
      content: extractedContent.join('\n').trim()
    };
  }

  return null;
}

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

    let smimeContent = smime;
    let extractedEmailContent = null;

    // Wenn die Daten Base64-encoded sind (von n8n), erst dekodieren
    if (!smime.includes('-----BEGIN') && !smime.includes('\n')) {
      try {
        // Versuche als Base64-encoded S/MIME zu dekodieren
        smimeContent = Buffer.from(smime, 'base64').toString('utf8');
        console.log('Decoded Base64 S/MIME data');
      } catch (e) {
        // Falls Dekodierung fehlschlägt, verwende Original
        console.log('Could not decode as Base64, using original data');
      }
    }

    // Prüfe ob es eine komplette E-Mail ist (multipart/signed)
    const emailParts = extractPKCS7FromEmail(smimeContent);
    if (emailParts) {
      console.log('Detected multipart/signed email, extracting PKCS#7 signature part');
      smimeContent = emailParts.signature;
      extractedEmailContent = emailParts.content;
    }

    // S/MIME Nachricht als PEM verarbeiten
    let p7;
    try {
      // PKCS7 Nachricht aus PEM oder raw format parsen
      if (smimeContent.includes('-----BEGIN')) {
        p7 = forge.pkcs7.messageFromPem(smimeContent);
      } else {
        // Versuche als base64/DER zu dekodieren
        const der = forge.util.decode64(smimeContent);
        const asn1 = forge.asn1.fromDer(der);
        p7 = forge.pkcs7.messageFromAsn1(asn1);
      }
    } catch (e) {
      return res.status(400).json({
        error: 'Invalid S/MIME format',
        message: 'Could not parse S/MIME message. Please provide valid PKCS#7/S/MIME format.',
        details: e.message,
        hint: 'S/MIME data can be provided as PEM format, Base64-encoded, multipart/signed email, or raw binary data'
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

      // Extrahiere Signer-Informationen und Content
      // Wenn wir den Content bereits aus der multipart/signed E-Mail extrahiert haben, nutze den
      if (extractedEmailContent) {
        result.content = extractedEmailContent;
      } else if (p7.rawCapture && p7.rawCapture.content) {
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

