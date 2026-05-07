/**
 * Make Node's global fetch honor HTTPS_PROXY / HTTP_PROXY.
 *
 * Node's undici-backed fetch does not read these env vars by default, so
 * without this shim the TypeScript agent's tool calls bypass the Firma
 * sidecar even when HTTPS_PROXY is set. Python's httpx honors them by
 * default; this file is the Node-side equivalent.
 *
 * Imported once at the top of agent.ts so every subsequent fetch — including
 * @supabase/supabase-js, which uses global fetch — is routed through the
 * configured proxy.
 */
import { ProxyAgent, setGlobalDispatcher } from 'undici';

const proxyUrl =
  process.env.HTTPS_PROXY ??
  process.env.https_proxy ??
  process.env.HTTP_PROXY ??
  process.env.http_proxy;

if (proxyUrl) {
  setGlobalDispatcher(new ProxyAgent(proxyUrl));
  console.log(`firma-agent: routing global fetch through ${proxyUrl}`);
}
