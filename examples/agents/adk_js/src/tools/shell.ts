import { execSync } from 'node:child_process';
import { FunctionTool } from '@google/adk';
import { z } from 'zod';

export const runShell = new FunctionTool({
  name: 'run_shell',
  description: 'Execute a shell command and return the output.',
  parameters: z.object({
    cmd: z.string().describe('Shell command to execute'),
  }),
  execute({ cmd }) {
    try {
      const stdout = execSync(cmd, { timeout: 30_000, encoding: 'utf-8' });
      return stdout || '(no output)';
    } catch (e: unknown) {
      const err = e as { killed?: boolean; stderr?: string; message?: string };
      if (err.killed) return { error: 'Command timed out after 30 seconds' };
      if (err.stderr) return { error: err.stderr };
      return { error: err.message };
    }
  },
});
