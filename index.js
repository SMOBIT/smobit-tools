const express = require('express');
const pdf = require('pdf-parse');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const forge = require('node-forge');
const mammoth = require('mammoth');
const cheerio = require('cheerio');
const multer = require('multer');

const app = express();

// Multer Setup für File Upload (Memory Storage)
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 30 * 1024 * 1024 // Max 30MB
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
      cb(null, true);
    } else {
      cb(new Error('Only .docx files are allowed'));
    }
  }
});

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
app.use('/convert-to-html', limiter);
app.use('/parse-html', limiter);

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
      convertToHtml: 'POST /convert-to-html - Convert DOCX to HTML (auth required, supports multipart/form-data or JSON with base64)',
      parseHtml: 'POST /parse-html - Parse HTML into structured JSON with enhanced table parsing: lists, paragraphs, hierarchies (auth required)',
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
      },
      {
        name: 'DOCX to HTML Converter',
        endpoint: '/convert-to-html',
        method: 'POST',
        description: 'Convert DOCX files to HTML while preserving structure (especially tables)',
        authentication: 'Required (X-API-Key header)',
        rateLimit: '100 requests per 15 minutes',
        maxFileSize: '30MB',
        contentType: 'multipart/form-data OR application/json',
        parameters: {
          document: 'DOCX file (binary upload, field name: document) - for multipart/form-data',
          base64: 'Base64 encoded DOCX data (optional) - for JSON requests'
        },
        output: 'HTML content with tables and formatting preserved',
        note: 'Supports both file upload (multipart/form-data) and Base64 JSON input'
      },
      {
        name: 'HTML Parser',
        endpoint: '/parse-html',
        method: 'POST',
        description: 'Parse HTML into structured JSON with enhanced table cell parsing (lists, paragraphs, hierarchies)',
        authentication: 'Required (X-API-Key header)',
        rateLimit: '100 requests per 15 minutes',
        maxFileSize: '10MB',
        parameters: {
          html: 'HTML content string (required)'
        },
        output: 'Structured JSON with tables array (with cell positions, lists, paragraphs, nested structures) and paragraphs array',
        features: [
          'Extracts lists (<ul>, <ol>) from table cells with nested list support',
          'Preserves paragraph structure within cells',
          'Detects line breaks (<br>) and multiple lines',
          'HTML preprocessing for better text extraction (e.g., "1Stk" → "1 Stk")',
          'Flags cells with structured content (has_structure)',
          'Maintains backwards compatibility with plain text field'
        ],
        note: 'Enhanced parser with structure preservation. Deterministic - same input always produces same output.'
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

// DOCX to HTML Converter Endpoint (mit API-Key Authentifizierung)
// Supports both multipart/form-data upload and JSON with base64
app.post('/convert-to-html', authenticateApiKey, (req, res, next) => {
  // Check if Content-Type is multipart/form-data
  const contentType = req.headers['content-type'] || '';
  if (contentType.includes('multipart/form-data')) {
    // Use multer for file upload
    upload.single('document')(req, res, next);
  } else {
    // Skip multer for JSON requests
    next();
  }
}, async (req, res) => {
  try {
    let buffer;
    let fileSize = 0;

    // Check if file was uploaded via multipart/form-data
    if (req.file) {
      buffer = req.file.buffer;
      fileSize = req.file.size;
    }
    // Check if base64 data was sent via JSON
    else if (req.body && req.body.base64) {
      try {
        buffer = Buffer.from(req.body.base64, 'base64');
        fileSize = buffer.length;

        // Check file size limit (30MB)
        if (fileSize > 30 * 1024 * 1024) {
          return res.status(400).json({
            success: false,
            error: 'File too large',
            message: 'Maximum file size is 30MB'
          });
        }
      } catch (e) {
        return res.status(400).json({
          success: false,
          error: 'Invalid base64 data',
          message: 'Could not decode base64 data'
        });
      }
    }
    // No file or base64 data provided
    else {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded',
        message: 'Please upload a .docx file with field name "document" (multipart/form-data) or provide "base64" parameter (JSON)'
      });
    }

    // Convert DOCX to HTML using mammoth
    const result = await mammoth.convertToHtml(
      { buffer: buffer },
      {
        // Preserve tables and structure
        includeDefaultStyleMap: true,
        includeEmbeddedStyleMap: true
      }
    );

    res.json({
      success: true,
      html: result.value,
      metadata: {
        messages: result.messages,
        size: fileSize
      }
    });

  } catch (error) {
    console.error('DOCX conversion error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to convert DOCX to HTML',
      message: error.message
    });
  }
});

// Helper function to preprocess HTML for better parsing
function preprocessHtml(html) {
  return html
    // Replace multiple tabs with single space
    .replace(/\t+/g, ' ')

    // Add space between lowercase and uppercase (e.g., "HerrTorsten" → "Herr Torsten")
    .replace(/([a-z])([A-Z])/g, '$1 $2')

    // Add space between number and uppercase (e.g., "1Stk" → "1 Stk")
    .replace(/([0-9])([A-Z])/g, '$1 $2')

    // Add space after period if followed by uppercase
    .replace(/\.([A-Z])/g, '. $1')

    // Normalize multiple spaces to single space
    .replace(/\s{2,}/g, ' ')

    .trim();
}

// Helper function to parse cell content with structure preservation
function parseCellContent($, cellElement) {
  const $cell = $(cellElement);

  // Extract lists (ul, ol)
  const lists = [];
  $cell.find('ul, ol').each((listIndex, listElement) => {
    const listType = listElement.tagName.toLowerCase(); // 'ul' or 'ol'
    const items = [];

    $(listElement).children('li').each((itemIndex, liElement) => {
      const $li = $(liElement);

      // Check for nested lists
      const nestedLists = [];
      $li.find('ul, ol').each((nestedIndex, nestedListElement) => {
        const nestedType = nestedListElement.tagName.toLowerCase();
        const nestedItems = [];

        $(nestedListElement).children('li').each((nestedItemIndex, nestedLiElement) => {
          nestedItems.push($(nestedLiElement).text().trim());
        });

        nestedLists.push({
          type: nestedType,
          items: nestedItems
        });
      });

      // Get text without nested list text
      let itemText = $li.clone();
      itemText.find('ul, ol').remove();
      itemText = itemText.text().trim();

      const listItem = {
        text: itemText
      };

      if (nestedLists.length > 0) {
        listItem.nestedLists = nestedLists;
      }

      items.push(listItem);
    });

    lists.push({
      type: listType,
      items: items
    });
  });

  // Extract paragraphs (direct p tags in cell)
  const paragraphs = [];
  $cell.children('p').each((pIndex, pElement) => {
    const text = $(pElement).text().trim();
    if (text) {
      paragraphs.push(text);
    }
  });

  // Extract line breaks - split by <br> tags
  const htmlContent = $cell.html() || '';
  const lines = htmlContent.split(/<br\s*\/?>/i).map(line => {
    // Remove HTML tags from each line and trim
    return cheerio.load(line).text().trim();
  }).filter(line => line.length > 0);

  // Get plain text as fallback
  const plainText = $cell.text().trim();

  // Determine if cell has structured content
  const hasStructure = lists.length > 0 || paragraphs.length > 0 || (lines.length > 1);

  return {
    text: plainText,
    lists: lists.length > 0 ? lists : undefined,
    paragraphs: paragraphs.length > 0 ? paragraphs : undefined,
    lines: lines.length > 1 ? lines : undefined, // Only include if multiple lines exist
    has_structure: hasStructure ? true : undefined // Only include if true
  };
}

// HTML Parser Endpoint (mit API-Key Authentifizierung)
app.post('/parse-html', authenticateApiKey, async (req, res) => {
  try {
    const { html } = req.body;

    if (!html) {
      return res.status(400).json({
        success: false,
        error: 'HTML content is required',
        message: 'Please provide the html parameter with HTML content'
      });
    }

    // Preprocess HTML for better text extraction
    const cleanedHtml = preprocessHtml(html);

    // Parse HTML with cheerio
    const $ = cheerio.load(cleanedHtml);

    // Extract all tables
    const tables = [];
    let structuredCellCount = 0;

    $('table').each((tableIndex, tableElement) => {
      const rows = [];
      let maxColumns = 0;

      $(tableElement).find('tr').each((rowIndex, rowElement) => {
        const rowCells = [];

        $(rowElement).find('td, th').each((colIndex, cellElement) => {
          const cellContent = parseCellContent($, cellElement);

          // Count structured cells
          if (cellContent.has_structure) {
            structuredCellCount++;
          }

          rowCells.push({
            ...cellContent,
            column: colIndex,
            row: rowIndex,
            isHeader: cellElement.tagName.toLowerCase() === 'th'
          });
        });

        if (rowCells.length > maxColumns) {
          maxColumns = rowCells.length;
        }

        rows.push(rowCells);
      });

      tables.push({
        index: tableIndex,
        rows: rows,
        columnCount: maxColumns,
        rowCount: rows.length
      });
    });

    // Extract all paragraphs
    const paragraphs = [];
    $('p').each((index, element) => {
      const text = $(element).text().trim();
      if (text) { // Only add non-empty paragraphs
        paragraphs.push(text);
      }
    });

    res.json({
      success: true,
      data: {
        tables: tables,
        paragraphs: paragraphs,
        metadata: {
          tableCount: tables.length,
          paragraphCount: paragraphs.length,
          structured_cells: structuredCellCount
        }
      }
    });

  } catch (error) {
    console.error('HTML parsing error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to parse HTML',
      message: error.message
    });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: ['/', '/health', '/tools', '/parse/pdf', '/parse/smime', '/convert-to-html', '/parse-html']
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

