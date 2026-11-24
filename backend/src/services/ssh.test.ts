import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Server as SshServer, utils } from 'ssh2';
import { afterEach, expect, it, vi } from 'vitest';
import type { Server } from '../types.js';
import { queryOne } from './db.js';
import { disconnectAll, getConnection } from './ssh.js';

vi.mock('./db.js', () => ({ queryOne: vi.fn() }));
vi.mock('./crypto.js', () => ({ decrypt: (value: string) => value }));

afterEach(() => {
  disconnectAll();
  vi.resetAllMocks();
});

it('requires the pinned host key before allowing SSH user authentication', async () => {
  const hostKeys = utils.generateKeyPairSync('ed25519');
  const loginKeys = utils.generateKeyPairSync('ed25519');
  const keyBlob = Buffer.from(hostKeys.public.split(' ')[1], 'base64');
  const fingerprint = `SHA256:${createHash('sha256').update(keyBlob).digest('base64').slice(0, -1)}`;
  const authMethods: string[] = [];
  const remote = new SshServer({ hostKeys: [hostKeys.private] }, client => {
    client.on('error', () => {});
    client.on('authentication', ctx => {
      authMethods.push(ctx.method);
      if (ctx.method === 'publickey') ctx.accept();
      else ctx.reject(['publickey']);
    });
  });
  await new Promise<void>((resolve, reject) => {
    remote.once('error', reject);
    remote.listen(0, '127.0.0.1', resolve);
  });
  const server: Server = {
    id: 'ssh-test',
    name: 'Test VPS',
    host: '127.0.0.1',
    port: (remote.address() as AddressInfo).port,
    username: 'vpn',
    auth_type: 'key',
    private_key: loginKeys.private,
    host_fingerprint: null,
  };
  try {
    vi.mocked(queryOne).mockReturnValue(server);
    await expect(getConnection(server)).rejects.toThrow('Укажите отпечаток SSH-хоста');

    server.host_fingerprint = `SHA256:${'A'.repeat(43)}`;
    await expect(getConnection(server)).rejects.toThrow('Отпечаток SSH-хоста не совпадает');
    expect(authMethods).toEqual([]);

    server.host_fingerprint = fingerprint;
    const ssh = await getConnection(server);
    expect(ssh.isConnected()).toBe(true);
    expect(authMethods).toContain('publickey');

    // A stale worker cannot keep using a cached connection after key rotation.
    vi.mocked(queryOne).mockReturnValue({ ...server, host_fingerprint: `SHA256:${'A'.repeat(43)}` });
    await expect(getConnection(server)).rejects.toThrow('Настройки SSH изменились');
  } finally {
    disconnectAll();
    await new Promise<void>(resolve => remote.close(() => resolve()));
  }
});
