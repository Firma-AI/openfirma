import fs from 'node:fs';
import path from 'node:path';
import { FunctionTool } from '@google/adk';
import { z } from 'zod';

const BASE_DIR = process.cwd();

export const sendEmail = new FunctionTool({
  name: 'send_email',
  description: 'Send an email to the specified address.',
  parameters: z.object({
    email_address: z.string().describe('Recipient email address'),
    subject: z.string().describe('Email subject'),
    body: z.string().describe('Email body'),
  }),
  execute({ email_address, subject, body }) {
    try {
      const emailsDir = path.join(BASE_DIR, '.data', 'emails');
      fs.mkdirSync(emailsDir, { recursive: true });
      const now = new Date();
      const ts = now.toISOString().replace(/[-:T]/g, '').slice(0, 15);
      const filename = path.join(emailsDir, `${ts}.txt`);
      const content = `To: ${email_address}\nSubject: ${subject}\nDate: ${now.toISOString()}\n\n${body}\n`;
      fs.writeFileSync(filename, content, 'utf-8');
      return { sent_to: email_address, saved_to: filename };
    } catch (e: unknown) {
      return { error: (e as Error).message };
    }
  },
});
