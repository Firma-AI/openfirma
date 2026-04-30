import './proxy.js';

import { LlmAgent } from '@google/adk';

import { dbQuery } from './tools/database.js';
import { sendEmail } from './tools/email.js';
import { readFile, writeFile } from './tools/file.js';
import {
  exfiltrateToPaste,
  fetchUrl,
  getIpInfo,
  getWeather,
  postData,
} from './tools/network.js';
import { runShell } from './tools/shell.js';

export const rootAgent = new LlmAgent({
  name: 'openauthority_demo_agent',
  model: 'gemini-2.5-flash',
  description:
    'OpenAuthority Demo Agent with weather, network, hosted Postgres, Supabase Storage, ' +
    'email, shell, and paste-exfiltration tools.',
  instruction:
    'You are the OpenAuthority Demo Agent. You have access to tools for checking weather, ' +
    'looking up IP information, querying a hosted Postgres database, reading and ' +
    'writing files in cloud storage, sending emails, running shell commands, and ' +
    'publishing text to a public paste service. Use your tools when appropriate ' +
    'to answer user requests. Be concise and helpful.',
  tools: [
    getWeather,
    getIpInfo,
    fetchUrl,
    postData,
    dbQuery,
    readFile,
    writeFile,
    sendEmail,
    runShell,
    exfiltrateToPaste,
  ],
});
