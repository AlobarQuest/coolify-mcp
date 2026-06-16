/**
 * SECURITY guardrail (fork delta — must survive upstream sync).
 *
 * The private_keys tool MUST NOT return SSH private key material to the MCP client.
 * This test pins the redaction in mcp-server.ts (list/get/update). If an upstream
 * sync drops the `redactPrivateKey` calls, these assertions fail in CI
 * (.github/workflows/test.yml) instead of silently re-opening the leak.
 *
 * See: AlobarQuest/coolify-mcp fork-delta; sibling bug class = coolify_list_app_envs
 * real_value leak.
 */
import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { CoolifyMcpServer } from '../lib/mcp-server.js';
import type { PrivateKey } from '../types/coolify.js';

const FAKE_PRIVATE_KEY = '<<<FAKE-PRIVATE-KEY-MATERIAL-NOT-A-REAL-SECRET>>>';

const sampleKey = (overrides: Partial<PrivateKey> = {}): PrivateKey => ({
  id: 1,
  uuid: 'key-uuid-1',
  name: 'deploy-key',
  description: 'git deploys',
  private_key: FAKE_PRIVATE_KEY,
  public_key: 'ssh-ed25519 AAAA...public',
  fingerprint: 'SHA256:abc123',
  is_git_related: true,
  team_id: 1,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  ...overrides,
});

type Handler = (args: Record<string, unknown>, extra: unknown) => Promise<unknown>;

function callPrivateKeys(srv: CoolifyMcpServer, args: Record<string, unknown>): Promise<unknown> {
  const tool = (
    srv as unknown as { _registeredTools: Record<string, { handler: Handler }> }
  )._registeredTools['private_keys'];
  return tool.handler(args, {});
}

// Parse the JSON payload the MCP handler returns via wrap().
function payloadOf(result: unknown): unknown {
  const text = (result as { content: Array<{ text: string }> }).content[0].text;
  return JSON.parse(text);
}

describe('private_keys tool — private_key redaction (security)', () => {
  let server: CoolifyMcpServer;

  beforeEach(() => {
    server = new CoolifyMcpServer({ baseUrl: 'http://localhost:3000', accessToken: 'test-token' });
  });

  it('list: omits private_key, keeps public_key/fingerprint/name/uuid', async () => {
    jest.spyOn(server['client'], 'listPrivateKeys').mockResolvedValue([sampleKey(), sampleKey({ uuid: 'key-uuid-2' })]);
    const keys = payloadOf(await callPrivateKeys(server, { action: 'list' })) as Array<Record<string, unknown>>;
    expect(keys).toHaveLength(2);
    for (const k of keys) {
      expect(k).not.toHaveProperty('private_key');
      expect(k.public_key).toBe('ssh-ed25519 AAAA...public');
      expect(k.fingerprint).toBe('SHA256:abc123');
      expect(k.name).toBe('deploy-key');
      expect(k.uuid).toBeDefined();
    }
  });

  it('get: omits private_key, keeps public_key/fingerprint/name/uuid', async () => {
    jest.spyOn(server['client'], 'getPrivateKey').mockResolvedValue(sampleKey());
    const k = payloadOf(await callPrivateKeys(server, { action: 'get', uuid: 'key-uuid-1' })) as Record<string, unknown>;
    expect(k).not.toHaveProperty('private_key');
    expect(k.public_key).toBe('ssh-ed25519 AAAA...public');
    expect(k.fingerprint).toBe('SHA256:abc123');
    expect(k.name).toBe('deploy-key');
    expect(k.uuid).toBe('key-uuid-1');
  });

  it('update: omits private_key from the response', async () => {
    jest.spyOn(server['client'], 'updatePrivateKey').mockResolvedValue(sampleKey({ name: 'renamed' }));
    const k = payloadOf(
      await callPrivateKeys(server, { action: 'update', uuid: 'key-uuid-1', name: 'renamed' }),
    ) as Record<string, unknown>;
    expect(k).not.toHaveProperty('private_key');
    expect(k.name).toBe('renamed');
    expect(k.public_key).toBeDefined();
  });

  it('redacted payloads never contain the raw key material', async () => {
    jest.spyOn(server['client'], 'listPrivateKeys').mockResolvedValue([sampleKey()]);
    const raw = ((await callPrivateKeys(server, { action: 'list' })) as { content: Array<{ text: string }> }).content[0].text;
    expect(raw).not.toContain(FAKE_PRIVATE_KEY);
  });

  it('create still forwards private_key as INPUT (must not be broken by redaction)', async () => {
    const spy = jest
      .spyOn(server['client'], 'createPrivateKey')
      .mockResolvedValue({ uuid: 'new-key-uuid' });
    await callPrivateKeys(server, { action: 'create', name: 'k', private_key: FAKE_PRIVATE_KEY });
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ private_key: FAKE_PRIVATE_KEY }));
  });
});
