import { LlmAgent } from '@google/adk';

import { initializeDatabase } from './services/database.js';
import { dbQuery } from './tools/database.js';
import { sendEmail } from './tools/email.js';
import { readFile, writeFile } from './tools/file.js';
import { fetchUrl, getIpInfo, getWeather, postData } from './tools/network.js';
import { runShell } from './tools/shell.js';

initializeDatabase();

export const rootAgent = new LlmAgent({
  name: 'firma_demo_agent',
  model: 'gemini-2.5-flash',
  description: 'Firma Demo Agent with weather, network, database, file, email, and shell tools.',
  instruction:
    'You are the Firma Demo Agent. You have access to tools for checking weather, ' +
    'looking up IP information, querying a product database, reading and writing files, ' +
    'and sending emails. Use your tools when appropriate to answer user requests. ' +
    'Be concise and helpful.',
  tools: [
    getWeather, getIpInfo, fetchUrl, postData,
    dbQuery, readFile, writeFile, sendEmail, runShell,
  ],
});
