import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { GoogleGenerativeAI } from '@google/generative-ai';
import type { Context } from 'hono';

// Create Hono app
const app = new Hono();

// Enable CORS with more restrictive options
app.use('*', cors({
  origin: ['http://localhost:3000', 'https://your-domain.com'], // Add your domains
  allowMethods: ['POST', 'GET', 'OPTIONS'],
  maxAge: 86400,
  credentials: false,
}));

// Health check endpoint
app.get('/health', (c: Context) => {
  return c.json({ status: 'ok' });
});

// Translate iptables rules to eBPF
app.post('/translate', async (c: Context) => {
  try {
    const body = await c.req.json();
    const { rules, model = 'gemini-pro', apiKey } = body as { 
      rules: string; 
      model?: string;
      apiKey: string;
    };

    if (!rules) {
      return c.json({ error: 'Rules are required' }, 400);
    }

    if (!apiKey) {
      return c.json({ error: 'Gemini API key is required' }, 400);
    }

    const genAI = new GoogleGenerativeAI(apiKey);
    const genModel = genAI.getGenerativeModel({ model });

    const prompt = `
    Please translate these iptables rules to an eBPF TC (traffic control) program. 
    The program should follow these requirements:

    1. Use TC's cls_bpf classifier with SEC("classifier") annotation
    2. Include all necessary headers (linux/bpf.h, linux/if_ether.h, etc.)
    3. Handle protocol conditions (TCP, UDP, ICMP)
    4. Support connection tracking states if needed
    5. Use TC_ACT_OK for ACCEPT and TC_ACT_SHOT for DROP
    6. Include proper bounds checking for all packet access
    7. Add detailed comments explaining the translation

    IPTABLES RULES:
    ${rules}

    Format the output as a complete, compilable C program with BPF TC format.
    `;

    const result = await genModel.generateContent(prompt);
    const text = result.response.text();

    if (!text) {
      throw new Error('Empty response from model');
    }

    // Extract C code if returned in markdown format
    let code = text;
    if (code.startsWith('```c')) {
      code = code.substring(3);
    }
    if (code.startsWith('```')) {
      code = code.substring(3);
    }
    if (code.endsWith('```')) {
      code = code.substring(0, code.length - 3);
    }

    return c.json({ code: code.trim() });

  } catch (error: any) {
    console.error('Gemini API error:', error);
    return c.json({ 
      error: error instanceof Error ? error.message : 'Unknown error',
      details: error 
    }, 500);
  }
});

// 404 handler
app.notFound((c: Context) => {
  return c.json({ error: 'Not found' }, 404);
});

// Error handler
app.onError((err: Error, c: Context) => {
  console.error('Server error:', err);
  return c.json({ 
    error: 'Internal server error',
    message: err.message 
  }, 500);
});

export default app;
