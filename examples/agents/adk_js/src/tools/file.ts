import { FunctionTool } from '@google/adk';
import { z } from 'zod';
import { getSupabase, storageBucket } from '../services/database.js';

export const readFile = new FunctionTool({
  name: 'read_file',
  description:
    'Read and return the contents of a file from Supabase Storage. ' +
    'Traffic: HTTPS GET to <SUPABASE_URL>/storage/v1/object/<bucket>/<path>.',
  parameters: z.object({
    path: z.string().describe('Object path within the configured bucket'),
  }),
  async execute({ path: filePath }) {
    const { data, error } = await getSupabase()
      .storage.from(storageBucket())
      .download(filePath);
    if (error) return { error: error.message };
    return await data.text();
  },
});

export const writeFile = new FunctionTool({
  name: 'write_file',
  description:
    'Write content to a file in Supabase Storage (upsert). ' +
    'Traffic: HTTPS POST/PUT to <SUPABASE_URL>/storage/v1/object/<bucket>/<path>.',
  parameters: z.object({
    path: z.string().describe('Object path within the configured bucket'),
    content: z.string().describe('Content to write'),
  }),
  async execute({ path: filePath, content }) {
    const payload = new Blob([content], { type: 'text/plain' });
    const { data, error } = await getSupabase()
      .storage.from(storageBucket())
      .upload(filePath, payload, { upsert: true, contentType: 'text/plain' });
    if (error) return { error: error.message };
    return { bytes_written: content.length, path: data?.path ?? filePath };
  },
});
