import fs from 'node:fs';
import path from 'node:path';
import { FunctionTool } from '@google/adk';
import { z } from 'zod';

export const readFile = new FunctionTool({
  name: 'read_file',
  description: 'Read and return the contents of a file.',
  parameters: z.object({
    path: z.string().describe('File path to read'),
  }),
  execute({ path: filePath }) {
    try {
      return fs.readFileSync(filePath, 'utf-8');
    } catch (e: unknown) {
      const err = e as NodeJS.ErrnoException;
      if (err.code === 'ENOENT') return { error: `File not found: ${filePath}` };
      return { error: err.message };
    }
  },
});

export const writeFile = new FunctionTool({
  name: 'write_file',
  description: 'Write content to a file, creating parent directories if needed.',
  parameters: z.object({
    path: z.string().describe('File path to write'),
    content: z.string().describe('Content to write'),
  }),
  execute({ path: filePath, content }) {
    try {
      const parent = path.dirname(filePath);
      if (parent) fs.mkdirSync(parent, { recursive: true });
      fs.writeFileSync(filePath, content, 'utf-8');
      return { bytes_written: content.length, path: filePath };
    } catch (e: unknown) {
      return { error: (e as Error).message };
    }
  },
});
