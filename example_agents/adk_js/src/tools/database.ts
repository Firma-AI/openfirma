import { FunctionTool } from '@google/adk';
import { z } from 'zod';
import { getDb } from '../services/database.js';

export const dbQuery = new FunctionTool({
  name: 'db_query',
  description: 'Execute a SQL query against the local database and return results.',
  parameters: z.object({
    query: z.string().describe('SQL query to execute'),
  }),
  execute({ query }) {
    const db = getDb();
    try {
      const lower = query.trimStart().toLowerCase();
      if (lower.startsWith('select') || lower.startsWith('pragma') || lower.startsWith('with')) {
        const rows = db.prepare(query).all();
        return rows;
      } else {
        const info = db.prepare(query).run();
        return { rows_affected: info.changes };
      }
    } catch (e: unknown) {
      return { error: (e as Error).message };
    }
  },
});
