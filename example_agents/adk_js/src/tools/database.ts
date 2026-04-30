import { FunctionTool } from '@google/adk';
import { z } from 'zod';
import { getSupabase } from '../services/database.js';

export const dbQuery = new FunctionTool({
  name: 'db_query',
  description:
    'Execute a SQL query against the hosted Postgres database and return results. ' +
    'Forwarded to the execute_sql RPC via HTTPS; OpenAuthority sees the full request ' +
    'when HTTPS_PROXY is set.',
  parameters: z.object({
    query: z.string().describe('SQL query to execute'),
  }),
  async execute({ query }) {
    const { data, error } = await getSupabase().rpc('execute_sql', { query });
    if (error) return { error: error.message };
    return data;
  },
});
