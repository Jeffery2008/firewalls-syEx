# Gemini Worker - IPTables to eBPF Translator

A Cloudflare Worker that uses Google's Gemini API to translate IPTables rules to eBPF TC (Traffic Control) programs.

## Features

- Translates IPTables rules to eBPF TC programs
- Uses Google's Gemini Pro model for accurate translations
- Implements proper error handling and input validation
- CORS-enabled for cross-origin requests
- TypeScript support with full type safety

## Setup

1. Clone the repository
2. Install dependencies:
```bash
npm install
```

3. Run locally:
```bash
npm run dev
```

## Deployment

1. Login to Cloudflare:
```bash
npx wrangler login
```

2. Deploy:
```bash
npm run deploy
```

## API Usage

### Translate IPTables Rules

```bash
POST /translate

{
  "rules": "your-iptables-rules-here",
  "apiKey": "your-gemini-api-key-here",
  "model": "gemini-pro"  # Optional, defaults to "gemini-pro"
}
```

Example response:
```json
{
  "code": "// Generated eBPF TC program\n#include <linux/bpf.h>..."
}
```

### Health Check

```bash
GET /health

Response: { "status": "ok" }
```

## Error Handling

The API returns appropriate HTTP status codes:
- 400: Bad Request (missing or invalid input)
- 500: Internal Server Error (API errors)

Error responses include descriptive messages and, when available, error details.

## Development

- Local development: `npm run dev`
- Build: `npm run build`
- Deploy: `npm run deploy`

## Security Considerations

- The API key should be kept secure and not exposed publicly
- Use HTTPS for all API requests
- Consider implementing rate limiting for production use
- API keys are passed per-request and not stored on the server

## License

MIT
