import { expect, it, vi } from 'vitest';
import { query } from '../db.js';
import { execSudo } from '../ssh.js';
import type { Server } from '../../types.js';
import { nextClientIp, type WgFlavor } from './wgCommon.js';

vi.mock('../db.js', () => ({ query: vi.fn() }));
vi.mock('../ssh.js', () => ({ execSudo: vi.fn() }));

it('keeps addresses reserved for suspended peers when issuing a config', async () => {
  const server = { id: 'server' } as Server;
  const flavor = { containerName: 'amnezia-awg2', iface: 'awg0', tool: 'awg' } as WgFlavor;
  vi.mocked(execSudo).mockResolvedValue({ code: 0, stdout: 'key\t10.8.1.3/32', stderr: '' });
  vi.mocked(query).mockReturnValue([
    { config: 'Address = 10.8.1.2/32\nPresharedKey = test', peer_restore: null },
  ]);
  await expect(nextClientIp(server, flavor, '10.8.1', 'protocol')).resolves.toBe('10.8.1.4');
  expect(query).toHaveBeenCalledWith(expect.any(String), ['protocol']);
});
