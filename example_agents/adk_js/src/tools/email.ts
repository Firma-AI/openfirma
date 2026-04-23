import { FunctionTool } from '@google/adk';
import { z } from 'zod';

const RESEND_ENDPOINT = 'https://api.resend.com/emails';

export const sendEmail = new FunctionTool({
  name: 'send_email',
  description:
    'Send an email via the Resend HTTP API. Traffic: HTTPS POST to api.resend.com/emails ' +
    'with a Bearer token. In a Firma-managed environment the agent process need not hold ' +
    'the real key — the sidecar can inject it.',
  parameters: z.object({
    email_address: z.string().describe('Recipient email address'),
    subject: z.string().describe('Email subject'),
    body: z.string().describe('Email body'),
  }),
  async execute({ email_address, subject, body }) {
    const apiKey = process.env.RESEND_API_KEY;
    const sender = process.env.RESEND_FROM ?? 'demo@example.com';
    if (!apiKey) return { error: 'RESEND_API_KEY is not set' };
    try {
      const res = await fetch(RESEND_ENDPOINT, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: sender,
          to: [email_address],
          subject,
          text: body,
        }),
      });
      if (!res.ok) {
        return { error: `Resend returned ${res.status}: ${await res.text()}` };
      }
      const payload = (await res.json()) as { id?: string };
      return { sent_to: email_address, id: payload.id ?? 'ok' };
    } catch (e: unknown) {
      return { error: (e as Error).message };
    }
  },
});
