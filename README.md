# SMOBIT Tools API

Tool-Server mit verschiedenen APIs für n8n Integration. Kann einfach über Coolify deployed werden.

## Features

- PDF Parser (URL oder Base64)
- API-Key Authentifizierung
- Rate Limiting (100 Requests / 15 Min)
- File-Size Limits (Max 10MB)
- Health Check Endpoint
- Einfache Integration mit n8n
- Docker-ready für Coolify Deployment

## Security

### API-Key Authentifizierung

Alle API-Endpoints (außer `/health` und `/`) erfordern einen API-Key.

**API-Key in Coolify setzen:**
1. In Coolify: Gehe zu deiner Application
2. Environment Variables → Add Variable
3. Key: `API_KEY`
4. Value: Dein sicherer API-Key (z.B. generiert mit `openssl rand -hex 32`)

**Lokal für Development:**
```bash
export API_KEY="your-secret-api-key"
npm start
```

### Rate Limiting

- Max 100 Requests pro 15 Minuten pro IP
- Bei Überschreitung: HTTP 429 (Too Many Requests)

### File-Size Limits

- Max Upload/Download: 10MB
- JSON Body Limit: 10MB

## Installation

### Lokal

```bash
npm install
npm start
```

Server läuft auf Port 3000 (oder PORT Environment Variable).

### Docker

```bash
docker build -t smobit-tools .
docker run -p 3000:3000 smobit-tools
```

### Coolify Deployment

1. Repository in Coolify hinzufügen
2. Branch: `main`
3. Build Pack: `Dockerfile` auswählen
4. Port: 3000
5. Health Check Path: `/health`
6. **WICHTIG:** Environment Variable setzen:
   - Key: `API_KEY`
   - Value: Dein sicherer API-Key (generiere einen mit `openssl rand -hex 32`)

**Beispiel API-Key generieren:**
```bash
openssl rand -hex 32
# Output: a1b2c3d4e5f6...
```

Diesen Key dann in Coolify als Environment Variable `API_KEY` setzen.

## API Endpoints

### GET /

API Übersicht und verfügbare Endpoints.

```bash
curl http://localhost:3000/
```

**Response:**
```json
{
  "name": "SMOBIT Tools API",
  "version": "1.0.0",
  "endpoints": {
    "health": "GET /health - Health check",
    "parsePdf": "POST /parse/pdf - Parse PDF from URL or base64",
    "tools": "GET /tools - List available tools"
  }
}
```

### GET /health

Health Check für Monitoring und Coolify.

```bash
curl http://localhost:3000/health
```

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-10-21T10:00:00.000Z",
  "uptime": 123.45,
  "version": "1.0.0"
}
```

### GET /tools

Liste aller verfügbaren Tools mit Parametern.

```bash
curl http://localhost:3000/tools
```

### POST /parse/pdf

PDF von URL oder Base64 parsen und Text extrahieren.

**Authentifizierung:** API-Key erforderlich (X-API-Key Header)

**Parameter:**
- `url` (optional): URL zum PDF
- `base64` (optional): Base64-encodiertes PDF

**Beispiel mit URL:**
```bash
curl -X POST http://localhost:3000/parse/pdf \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{"url": "https://example.com/document.pdf"}'
```

**Beispiel mit Base64:**
```bash
curl -X POST http://localhost:3000/parse/pdf \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{"base64": "JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PC..."}'
```

**Response:**
```json
{
  "success": true,
  "text": "Extrahierter Text aus dem PDF...",
  "pages": 5,
  "info": {
    "Title": "Dokument Titel",
    "Author": "Autor Name"
  },
  "metadata": {},
  "version": "1.7"
}
```

**Fehler Response:**
```json
{
  "success": false,
  "error": "Failed to parse PDF",
  "message": "Detailed error message"
}
```

## n8n Integration

### HTTP Request Node Konfiguration

1. **Method:** POST
2. **URL:** `https://your-domain.com/parse/pdf`
3. **Authentication:** None (wir nutzen Header)
4. **Headers:**
   - Name: `X-API-Key`
   - Value: `your-api-key-here` (oder aus n8n Credentials)
5. **Body Content Type:** JSON
6. **Body:**
```json
{
  "url": "{{$json.pdfUrl}}"
}
```

**Sicherer: API-Key als n8n Credential speichern:**
1. In n8n: Credentials → New Credential → Header Auth
2. Name: `SMOBIT Tools API Key`
3. Header Name: `X-API-Key`
4. Header Value: Dein API-Key
5. Im HTTP Request Node: Authentication → Header Auth → Credential auswählen

Der extrahierte Text ist dann verfügbar unter: `{{$json.text}}`

### Beispiel Workflow

1. **Trigger** (z.B. Webhook oder Schedule)
2. **HTTP Request** zu `/parse/pdf`
3. **Set Node** um den Text weiterzuverarbeiten
4. **Weitere Nodes** für deine Logik

## Neue Tools hinzufügen

Du kannst einfach weitere Endpoints in `index.js` hinzufügen:

```javascript
app.post('/parse/excel', async (req, res) => {
  // Deine Excel-Parser Logik
  res.json({ data: parsedData });
});
```

Vergiss nicht, die neue Tool-Definition in `/tools` zu ergänzen!

## Environment Variables

- `PORT`: Server Port (default: 3000)
- `API_KEY`: **WICHTIG!** API-Key für Authentifizierung (default: 'change-me-in-production')

**Security Warning:** Der Default API-Key sollte NIEMALS in Production verwendet werden! Setze immer einen sicheren API-Key in Coolify.

## Technologie

- Node.js 18+
- Express.js
- express-rate-limit (Rate Limiting)
- pdf-parse (PDF Parsing)
- axios (HTTP Client)

## Lizenz

MIT