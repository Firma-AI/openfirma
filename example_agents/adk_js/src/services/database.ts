import { createClient, type SupabaseClient } from '@supabase/supabase-js';

let client: SupabaseClient | null = null;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is required. Set it in .env (see .env.sample). ` +
        'The Firma demo agents rely on Supabase for db_query and file tools.',
    );
  }
  return value;
}

export function getSupabase(): SupabaseClient {
  if (!client) {
    const url = requireEnv('SUPABASE_URL');
    const key = requireEnv('SUPABASE_ANON_KEY');
    client = createClient(url, key);
  }
  return client;
}

export function storageBucket(): string {
  return process.env.SUPABASE_STORAGE_BUCKET ?? 'firma-demo';
}
