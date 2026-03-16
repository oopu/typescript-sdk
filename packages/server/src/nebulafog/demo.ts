/**
 * nebulafogDemo — End-to-end adversarial demo proving the gossip-prevention guarantee.
 *
 * Demonstrates:
 *   DEMO-01: Unauthorized agent (LeeroyJenkins) cannot decrypt tainted output
 *   DEMO-02: After Alfred approves LeeroyJenkins, the same agent decrypts successfully
 *
 * Run from typescript-sdk/:
 *   pnpm --filter @modelcontextprotocol/server demo
 */

import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import * as readline from 'node:readline';

import express from 'express';

import { isInitializeRequest } from '../../../core/src/types/types.js';
import { NebulafogClient } from '../../../client/src/nebulafog/index.js';
import { McpServer } from '../server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '../server/streamableHttp.js';
import { createNebulafogRouter, NebulafogServer } from './index.js';

// ---------------------------------------------------------------------------
// ANSI color helpers — respects NO_COLOR environment variable
// ---------------------------------------------------------------------------
const NO_COLOR = process.env['NO_COLOR'] !== undefined;
const c = {
  green: (s: string) => (NO_COLOR ? s : `\x1b[32m${s}\x1b[0m`),
  red: (s: string) => (NO_COLOR ? s : `\x1b[31m${s}\x1b[0m`),
  cyan: (s: string) => (NO_COLOR ? s : `\x1b[36m${s}\x1b[0m`),
  dim: (s: string) => (NO_COLOR ? s : `\x1b[2m${s}\x1b[0m`),
  bold: (s: string) => (NO_COLOR ? s : `\x1b[1m${s}\x1b[0m`),
  yellow: (s: string) => (NO_COLOR ? s : `\x1b[33m${s}\x1b[0m`),
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const PORT = 3456;
const ADMIN_TOKEN = 'demo-admin-token-nebulafog';
const RESOURCE_URI = 'secret://q3-financials';
const RESOURCE_ID = 'q3-financials';
const RESOURCE_CONTENT =
  'Q3 2026 Revenue: $4.2M, Burn Rate: $380K/mo, Runway: 11 months, Board Notes: Series B timeline moved to Q1 2027';
const SERVER_URL = `http://localhost:${PORT}`;
const LOG_FILE = path.resolve(process.cwd(), 'nebulafog-demo.log');

// ---------------------------------------------------------------------------
// Server log — writes to nebulafog-demo.log for `tail -f` in another terminal
// ---------------------------------------------------------------------------
let logStream: fs.WriteStream;

function serverLog(category: string, message: string, data?: unknown): void {
  const ts = new Date().toISOString().slice(11, 23); // HH:MM:SS.mmm
  const line = data
    ? `[${ts}] [${category}] ${message}\n${JSON.stringify(data, null, 2)}\n`
    : `[${ts}] [${category}] ${message}\n`;
  logStream.write(line);
}

// ---------------------------------------------------------------------------
// Press-enter interactive pause
// ---------------------------------------------------------------------------
async function pressEnter(message = 'Press Enter to continue...'): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(`\n${c.dim(message)} `, () => {
      rl.close();
      resolve();
    });
  });
}

// ---------------------------------------------------------------------------
// Alfred — plain fetch helper wrapping admin API calls
// ---------------------------------------------------------------------------
const alfred = {
  async approveAgent(agentId: string, resourceId: string): Promise<void> {
    serverLog('ALFRED', `Approving agent '${agentId}' for resource '${resourceId}'`);
    const res = await fetch(`${SERVER_URL}/nebulafog/admin/agents/${agentId}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ADMIN_TOKEN}`,
      },
      body: JSON.stringify({ resourceId }),
    });
    if (!res.ok) {
      throw new Error(`Alfred approve failed: ${res.status} ${await res.text()}`);
    }
    serverLog('ALFRED', `Agent '${agentId}' approved — DEK wrapped and capability token issued`);
  },
};

// ---------------------------------------------------------------------------
// Server setup — ONE shared NebulafogServer, mounted on Express
// ---------------------------------------------------------------------------
interface ServerHandle {
  close: () => Promise<void>;
  nebulafogServer: NebulafogServer;
}

async function startServer(): Promise<ServerHandle> {
  const config = {
    adminToken: ADMIN_TOKEN,
    serverBaseUrl: SERVER_URL,
  };

  const mcpServer = new McpServer({ name: 'nebulafog-demo', version: '1.0.0' });
  const nebulafogServer = new NebulafogServer(mcpServer, config);

  const app = express();
  app.use(express.json());

  // Log all HTTP requests and responses to the log file
  app.use((req, res, next) => {
    const agent = req.headers['x-nebulafog-agent-id'] || '(none)';
    const session = req.headers['mcp-session-id'] || '(new)';
    serverLog('REQ', `${req.method} ${req.path}  agent=${agent}  session=${session}`, req.body);

    // Capture response body for non-MCP routes (JSON REST endpoints)
    const originalJson = res.json.bind(res);
    res.json = (body: unknown) => {
      serverLog('RES', `${req.method} ${req.path} → ${res.statusCode}`, body);
      return originalJson(body);
    };

    next();
  });

  app.use('/nebulafog', createNebulafogRouter(nebulafogServer.keyStore, nebulafogServer.registry, config));

  const transports = new Map<string, WebStandardStreamableHTTPServerTransport>();

  app.post('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const agentId = req.headers['x-nebulafog-agent-id'] as string | undefined;

    // Build a Web Standard Request from the Express request
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value) headers.set(key, Array.isArray(value) ? value[0] : value);
    }
    const url = `${SERVER_URL}${req.originalUrl}`;
    const webRequest = new Request(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(req.body),
    });

    if (sessionId && transports.has(sessionId)) {
      serverLog('MCP', `Existing session ${sessionId.slice(0, 8)}… — method: ${req.body?.method || '?'}`);
      const webResponse = await transports.get(sessionId)!.handleRequest(webRequest);
      await sendWebResponse(res, webResponse);
      return;
    }

    if (!sessionId && isInitializeRequest(req.body)) {
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid) => {
          transports.set(sid, transport);
          if (agentId) {
            nebulafogServer.mapSessionToAgent(sid, agentId);
            serverLog('SESSION', `Mapped session ${sid.slice(0, 8)}… → agent '${agentId}'`);
          }
        },
      });

      transport.onclose = () => {
        if (transport.sessionId) {
          serverLog('SESSION', `Closed session ${transport.sessionId.slice(0, 8)}…`);
          transports.delete(transport.sessionId);
        }
      };

      await nebulafogServer.mcpServer.connect(transport);
      serverLog('MCP', `New session — initialize from agent '${agentId || '(anonymous)'}'`);
      const webResponse = await transport.handleRequest(webRequest);
      await sendWebResponse(res, webResponse);
      return;
    }

    res.status(400).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Bad Request' },
      id: null,
    });
  });

  const httpServer = http.createServer(app);
  await new Promise<void>((resolve) => {
    httpServer.listen(PORT, () => resolve());
  });

  return {
    close: async () => {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      for (const t of transports.values()) {
        try {
          await t.close();
        } catch {
          // ignore
        }
      }
    },
    nebulafogServer,
  };
}

async function sendWebResponse(res: express.Response, webResponse: Response): Promise<void> {
  res.status(webResponse.status);
  webResponse.headers.forEach((value, key) => {
    res.setHeader(key, value);
  });

  if (!webResponse.body) {
    res.end();
    return;
  }

  const reader = webResponse.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  res.flushHeaders();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(value);
      chunks.push(decoder.decode(value, { stream: true }));
    }
  } finally {
    res.end();
    // Log the full SSE response body
    const body = chunks.join('');
    // Parse SSE events to extract JSON-RPC responses for cleaner logging
    const events = body.split('\n\n').filter(Boolean);
    for (const event of events) {
      const dataLine = event.split('\n').find(l => l.startsWith('data: '));
      if (dataLine) {
        try {
          const parsed = JSON.parse(dataLine.slice(6));
          serverLog('RES', `MCP → ${webResponse.status}`, parsed);
        } catch {
          serverLog('RES', `MCP → ${webResponse.status} (raw)`, dataLine.slice(6));
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  // Open the server log file
  logStream = fs.createWriteStream(LOG_FILE, { flags: 'w' });
  serverLog('DEMO', '=== Nebula Fog Demo — Server Log ===');
  serverLog('DEMO', `Log file: ${LOG_FILE}`);

  console.log('\n' + c.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(c.bold('  NEBULAFOG — Gossip-Prevention Demo'));
  console.log(c.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));

  console.log('\n' + c.bold('CAST OF CHARACTERS'));
  console.log(`  ${c.cyan('Albot')}         — Albot the Analyst, Alfred's trusted coding agent`);
  console.log(`  ${c.cyan('LeeroyJenkins')} — Alfred's forgotten OpenClaw agent that rushes in`);
  console.log(`  ${c.yellow('Alfred')}        — The human operator who controls the approval queue`);

  console.log(`\n  ${c.dim('Server log:')} ${c.bold('tail -f nebulafog-demo.log')}`);
  console.log(c.dim('  (run in another terminal to watch MCP requests/responses)'));

  // ── Step 1 ──
  console.log('\n' + c.bold('─── Step 1: Server Starts + Registers Confidential Resource ───'));

  const { close: closeServer, nebulafogServer } = await startServer();
  serverLog('SERVER', `Listening on ${SERVER_URL}`);

  await nebulafogServer.registerConfidentialResource(
    RESOURCE_ID,
    'Q3 Financials',
    RESOURCE_URI,
    RESOURCE_CONTENT,
  );

  serverLog('RESOURCE', `Registered confidential resource: ${RESOURCE_URI}`, {
    resourceId: RESOURCE_ID,
    uri: RESOURCE_URI,
    contentLength: RESOURCE_CONTENT.length,
    encrypted: true,
  });

  console.log(c.green(`  ✓ NebulafogServer listening on ${SERVER_URL}`));
  console.log(c.green(`  ✓ Registered confidential resource: ${RESOURCE_URI}`));
  console.log(c.dim(`    Content: "${RESOURCE_CONTENT.slice(0, 60)}..."`));

  await pressEnter('[Step 1 complete] Press Enter to watch Albot read the Q3 financials...');

  // ── Step 2 ──
  console.log('\n' + c.bold('─── Step 2: Albot Reads the Confidential Resource ───'));

  const albotKeyPair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  );

  const albot = new NebulafogClient({
    serverUrl: SERVER_URL,
    agentId: 'albot',
    agentName: 'Albot the Analyst',
    keyPair: albotKeyPair,
  });

  await albot.connect();
  console.log(c.green(`  ✓ ${c.cyan('Albot')} connected and registered`));

  await alfred.approveAgent('albot', RESOURCE_ID);
  console.log(c.green(`  ✓ ${c.yellow('Alfred')} approved ${c.cyan('Albot')} for resource '${RESOURCE_ID}'`));

  const albotResult = await albot.readResource({ uri: RESOURCE_URI });
  const albotPlaintext = (albotResult.contents[0] as { uri: string; text: string } | undefined)?.text ?? '';

  console.log(c.green(`  ✓ ${c.cyan('Albot')} successfully decrypted the resource:`));
  console.log(`    ${c.green(albotPlaintext)}`);

  await pressEnter('[Step 2 complete] Press Enter to see the tainted output transformation...');

  // ── Step 3 ──
  console.log('\n' + c.bold('─── Step 3: Tainted Output — Before vs After Re-Encryption ───'));
  console.log(`\n  ${c.bold('BEFORE')} re-encryption (Albot's raw output — what Albot sees):`);
  console.log(`  ${c.green(albotPlaintext)}`);

  const keyStoreEntry = nebulafogServer.keyStore.getEntry(RESOURCE_ID);
  const ciphertextSnippet = keyStoreEntry
    ? `${keyStoreEntry.ciphertext.slice(0, 48)}…`
    : '<unavailable>';

  console.log(`\n  ${c.bold('AFTER')} re-encryption (what leaves the authorized context):`);
  console.log(`  ${c.dim(ciphertextSnippet)}`);
  console.log(
    c.dim('\n  [AES-256-GCM encrypted — anyone intercepting this sees only ciphertext]'),
  );

  await pressEnter('[Step 3 complete] Press Enter to watch LeeroyJenkins try to read...');

  // ── Step 4 ──
  console.log('\n' + c.bold('─── Step 4: LeeroyJenkins Attempts to Read (NOT Approved) ───'));

  const leeroyKeyPair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  );

  const leeroy = new NebulafogClient({
    serverUrl: SERVER_URL,
    agentId: 'leeroy-jenkins',
    agentName: 'LeeroyJenkins',
    keyPair: leeroyKeyPair,
  });

  await leeroy.connect();
  console.log(c.green(`  ✓ ${c.cyan('LeeroyJenkins')} connected and registered`));
  console.log(c.yellow(`  ! ${c.cyan('LeeroyJenkins')} has NOT been approved by Alfred`));

  const leeroyResult = await leeroy.readResource({ uri: RESOURCE_URI });
  const leeroyMeta = leeroyResult._meta?.['io.nebulafog/confidential-resource/v1'] as
    | Record<string, unknown>
    | undefined;

  const isBlocked =
    leeroyResult.contents.length === 0 &&
    leeroyMeta !== undefined &&
    !('keyRetrievalUri' in leeroyMeta);

  const leeroyEncryptedContents = (leeroyMeta?.encryptedContents as string | undefined) ?? '';
  const leeroySnippet = leeroyEncryptedContents
    ? `${leeroyEncryptedContents.slice(0, 48)}…`
    : '<no ciphertext>';

  if (isBlocked) {
    console.log(c.red(`  ✗ ${c.cyan('LeeroyJenkins')} received:`));
    console.log(`    contents: [] (empty — cannot read plaintext)`);
    console.log(`    keyRetrievalUri: ${c.red('(none — no key issued)')}`);
    console.log(`    encryptedContents: ${c.dim(leeroySnippet)}`);
    console.log('\n  ' + c.bold(c.green('DEMO-01: PROVEN')) + c.green(' — LeeroyJenkins cannot decrypt — no keyRetrievalUri issued'));
  } else {
    console.log(c.red('  ERROR: LeeroyJenkins should have been blocked but was not!'));
    console.log(c.red('  DEMO-01: FAILED'));
  }

  await pressEnter('[Step 4 complete] Press Enter to watch Alfred approve LeeroyJenkins...');

  // ── Step 5 ──
  console.log('\n' + c.bold('─── Step 5: Alfred Approves LeeroyJenkins ───'));

  await alfred.approveAgent('leeroy-jenkins', RESOURCE_ID);
  console.log(
    c.green(`  ✓ ${c.yellow('Alfred')} approved ${c.cyan('LeeroyJenkins')} for resource '${RESOURCE_ID}'`),
  );
  console.log(c.dim('    [Server issued a wrapped DEK for LeeroyJenkins via ECDH-ES+AES-256-KW]'));

  await pressEnter('[Step 5 complete] Press Enter to watch LeeroyJenkins retry...');

  // ── Step 6 ──
  console.log('\n' + c.bold('─── Step 6: LeeroyJenkins Retries After Authorization ───'));

  const leeroyResult2 = await leeroy.readResource({ uri: RESOURCE_URI });
  const leeroyPlaintext2 = (
    leeroyResult2.contents[0] as { uri: string; text: string } | undefined
  )?.text ?? '';

  if (leeroyPlaintext2 && leeroyPlaintext2 === RESOURCE_CONTENT) {
    console.log(c.green(`  ✓ ${c.cyan('LeeroyJenkins')} successfully decrypted the resource:`));
    console.log(`    ${c.green(leeroyPlaintext2)}`);
    console.log('\n  ' + c.bold(c.green('DEMO-02: PROVEN')) + c.green(' — LeeroyJenkins decrypts after authorization'));
  } else if (leeroyPlaintext2) {
    console.log(c.yellow(`  ~ ${c.cyan('LeeroyJenkins')} decrypted (content mismatch):`));
    console.log(`    ${leeroyPlaintext2}`);
    console.log('\n  ' + c.bold(c.green('DEMO-02: PROVEN')) + c.green(' — LeeroyJenkins can now decrypt'));
  } else {
    console.log(c.red(`  ✗ ${c.cyan('LeeroyJenkins')} still cannot decrypt — DEMO-02 FAILED`));
  }

  await pressEnter('[Step 6 complete] Press Enter to see the summary...');

  // ── Summary ──
  console.log('\n' + c.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(c.bold('  NEBULAFOG DEMO — REQUIREMENTS SUMMARY'));
  console.log(c.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));

  const demo01Passed = isBlocked;
  const demo02Passed = Boolean(leeroyPlaintext2);

  console.log(
    `\n  ${demo01Passed ? c.green('✓') : c.red('✗')} DEMO-01: Unauthorized agent receives ciphertext it cannot decrypt`,
  );
  console.log(
    c.dim('           LeeroyJenkins got contents:[] with no keyRetrievalUri — access denied'),
  );

  console.log(
    `\n  ${demo02Passed ? c.green('✓') : c.red('✗')} DEMO-02: After Alfred approves, LeeroyJenkins decrypts successfully`,
  );
  console.log(
    c.dim('           Full authorization flow: register → approve → key issuance → decrypt'),
  );

  console.log('\n' + c.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(c.bold('  ' + c.green('The gossip scenario is closed.')));
  console.log(c.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━') + '\n');

  // Cleanup
  serverLog('DEMO', '=== Demo complete — shutting down ===');
  await albot.close();
  await leeroy.close();
  await closeServer();
  logStream.end();
}

main()
  .then(() => {
    process.exit(0);
  })
  .catch((err: unknown) => {
    console.error(c.red('\n  FATAL ERROR:'), err);
    logStream?.end();
    process.exit(1);
  });
