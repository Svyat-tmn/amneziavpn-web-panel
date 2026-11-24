import { createHash } from 'node:crypto';
import { NodeSSH } from 'node-ssh';
import { decrypt } from './crypto.js';
import { queryOne } from './db.js';
import { UserError } from './errors.js';
import type { Server, ExecResult } from '../types.js';

export const SSH_HOST_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$/;

const connections = new Map<string, Promise<NodeSSH>>();

// Сообщения, по которым считаем что SSH-канал умер и нужно переподключиться.
const RECONNECT_PATTERNS = [
  /not connected/i,
  /connection lost/i,
  /channel closed/i,
  /no response/i,
  /ECONNRESET/,
  /EPIPE/,
  /Client network socket/i,
];

function shouldReconnect(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return RECONNECT_PATTERNS.some(re => re.test(msg));
}

export async function getConnection(server: Server): Promise<NodeSSH> {
  const key = server.id;
  // A worker may hold a server snapshot from before an edit or key rotation.
  const current = queryOne<Server>('SELECT * FROM servers WHERE id = ?', [key]);
  if (!current) throw new UserError('SSH-сервер удалён из панели');
  if (current.host !== server.host || current.port !== server.port ||
      current.host_fingerprint !== server.host_fingerprint) {
    throw new UserError('Настройки SSH изменились. Повторите операцию');
  }
  const fingerprint = current.host_fingerprint;
  if (!fingerprint || !SSH_HOST_FINGERPRINT.test(fingerprint)) {
    throw new UserError('Укажите отпечаток SSH-хоста в настройках сервера');
  }
  let pending = connections.get(key);
  if (!pending) {
    pending = connect(current, fingerprint);
    connections.set(key, pending);
  }
  try {
    const ssh = await pending;
    if (connections.get(key) !== pending) {
      throw new UserError('SSH-соединение сброшено. Повторите операцию');
    }
    return ssh;
  } catch (error) {
    if (connections.get(key) === pending) connections.delete(key);
    throw error;
  }
}

async function connect(server: Server, fingerprint: string): Promise<NodeSSH> {
  const ssh = new NodeSSH();
  let hostKeyRejected = false;
  const config: Parameters<NodeSSH['connect']>[0] = {
    host: server.host,
    port: server.port || 22,
    username: server.username,
    hostVerifier: (key: Buffer) => {
      const digest = createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
      hostKeyRejected = `SHA256:${digest}` !== fingerprint;
      return !hostKeyRejected;
    },
    readyTimeout: 15000,
    // Пингуем канал каждые 30s; если 3 пинга подряд не получили ответа — рвём.
    keepaliveInterval: 30000,
    keepaliveCountMax: 3,
  };

  if (server.auth_type === 'key') {
    const privateKey = decrypt(server.private_key);
    if (!privateKey) throw new UserError('Укажите приватный SSH-ключ для входа на сервер');
    config.privateKey = privateKey;
  } else {
    config.password = decrypt(server.password) as string;
  }

  try {
    await ssh.connect(config);
  } catch (error) {
    ssh.dispose();
    if (hostKeyRejected) {
      throw new UserError('Отпечаток SSH-хоста не совпадает. Проверьте ключ сервера по доверенному каналу');
    }
    throw error;
  }
  return ssh;
}

async function execOnce(server: Server, command: string): Promise<ExecResult> {
  const ssh = await getConnection(server);
  const result = await ssh.execCommand(command);
  return {
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    code: result.code,
  };
}

export async function exec(server: Server, command: string): Promise<ExecResult> {
  try {
    return await execOnce(server, command);
  } catch (e) {
    if (!shouldReconnect(e)) throw e;
    disconnect(server.id);
    return await execOnce(server, command);
  }
}

export async function execSudo(server: Server, command: string): Promise<ExecResult> {
  return exec(server, `sudo bash -c '${command.replace(/'/g, "'\\''")}'`);
}

export function disconnect(serverId: string): void {
  const pending = connections.get(serverId);
  connections.delete(serverId);
  if (pending) void pending.then(ssh => ssh.dispose()).catch(() => {});
}

export function disconnectAll(): void {
  for (const id of [...connections.keys()]) disconnect(id);
}

export interface TestConnectionResult {
  ok: boolean;
  info?: string;
  dockerAvailable?: boolean;
  error?: string;
}

export async function testConnection(server: Server): Promise<TestConnectionResult> {
  try {
    const ssh = await getConnection(server);
    const result = await ssh.execCommand('uname -a && docker --version 2>/dev/null || echo "docker-not-found"');
    return {
      ok: true,
      info: result.stdout,
      dockerAvailable: !result.stdout.includes('docker-not-found'),
    };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
