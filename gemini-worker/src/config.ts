export interface Config {
  GEMINI_API_KEY: string;
}

// wrangler.toml env vars are exposed on env.GEMINI_API_KEY
export function getConfig(env: any): Config {
  return {
    GEMINI_API_KEY: env.GEMINI_API_KEY || '',
  };
}
