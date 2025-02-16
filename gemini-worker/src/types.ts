// Request types
export interface TranslateRequest {
  rules: string;
  apiKey: string;
  model?: string;
}

// Response types
export interface TranslateResponse {
  code: string;
}

export interface ErrorResponse {
  error: string;
  details?: unknown;
}

export interface HealthResponse {
  status: 'ok';
}
