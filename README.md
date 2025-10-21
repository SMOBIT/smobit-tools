# SMOBIT Tools API

Tool-Server mit verschiedenen APIs für n8n Integration. Kann einfach über Coolify deployed werden.

## Features

- PDF Parser (URL oder Base64)
- Health Check Endpoint
- Einfache Integration mit n8n
- Docker-ready für Coolify Deployment

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
2. Als Node.js Application konfigurieren
3. Port: 3000
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Health Check Path: `/health`

Oder Dockerfile-basiert deployen (automatisch erkannt).

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

**Parameter:**
- `url` (optional): URL zum PDF
- `base64` (optional): Base64-encodiertes PDF

**Beispiel mit URL:**
```bash
curl -X POST http://localhost:3000/parse/pdf \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/document.pdf"}'
```

**Beispiel mit Base64:**
```bash
curl -X POST http://localhost:3000/parse/pdf \
  -H "Content-Type: application/json" \
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

1. Method: POST
2. URL: `https://your-domain.com/parse/pdf`
3. Body Content Type: JSON
4. Body:
```json
{
  "url": "{{$json.pdfUrl}}"
}
```

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

## Technologie

- Node.js 18+
- Express.js
- pdf-parse
- axios

## Lizenz

MIT