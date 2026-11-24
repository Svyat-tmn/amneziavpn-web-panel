// Операции над клиентом, затрагивающие сервер: отзыв пира, возврат пира и
// полное удаление. Раньше это жило прямо в routes/clients.ts, но с появлением
// лимитов те же действия выполняет фоновый воркер — а расходиться этим двум
// путям нельзя: «удалён в панели, но работает на сервере» это дыра, а не баг
// отображения.
import { queryOne, run } from './db.js';
import {
  removeAWG2Client, removeXrayClient, removeWireGuardClient, removeTelemtClient,
  restoreAWG2Client, restoreXrayClient, restoreWireGuardClient, restoreTelemtClient,
} from './protocols/index.js';
import { extractPeerRestoreInfo, type PeerRestoreInfo } from './peerId.js';
import { deleteSubscription } from './subscription.js';
import { UserError } from './errors.js';
import { decrypt, encrypt } from './crypto.js';
import { readContainerFile } from './protocols/common.js';
import { assertContainerName } from './shell.js';
import { isIPv4 } from 'node:net';
import type { Client, Protocol, Server } from '../types.js';

export interface ClientContext {
  client: Client;
  protocol: Protocol | null;
  server: Server | null;
}

export function loadClientContext(client: Client): ClientContext {
  const protocol = queryOne<Protocol>('SELECT * FROM protocols WHERE id = ?', [client.protocol_id]);
  const server = protocol
    ? queryOne<Server>('SELECT * FROM servers WHERE id = ?', [protocol.server_id])
    : null;
  return { client, protocol, server };
}

// Снимает пира на сервере. Бросает — вызывающий решает, что делать с записью:
// удалять её при неудавшемся отзыве нельзя, иначе «удалённый» клиент останется
// рабочим и невидимым.
export async function revokePeer(ctx: ClientContext): Promise<void> {
  const { client, protocol, server } = ctx;
  // Нечего отзывать: импортированный клиент без peer_id либо протокол/сервер
  // уже удалены вместе со всеми пирами.
  if (!client.peer_id || !protocol || !server) return;

  if      (protocol.type === 'awg2')      await removeAWG2Client(server, protocol, client.peer_id);
  else if (protocol.type === 'xray')      await removeXrayClient(server, protocol, client.peer_id);
  else if (protocol.type === 'wireguard') await removeWireGuardClient(server, protocol, client.peer_id);
  else if (protocol.type === 'telemt')    await removeTelemtClient(server, protocol, client.peer_id);
}

// Возвращает пира тем же ключом. Всё нужное лежит в сохранённом конфиге клиента,
// поэтому выданный ему профиль остаётся рабочим.
export async function restorePeer(ctx: ClientContext): Promise<void> {
  const { client, protocol, server } = ctx;
  if (!client.peer_id || !protocol || !server) {
    throw new UserError('Не хватает данных для возврата клиента на сервер (протокол или сервер удалены)');
  }

  const stored = decrypt(client.peer_restore);
  const info: PeerRestoreInfo | null = stored ? JSON.parse(stored) : extractPeerRestoreInfo(client.config ?? null, protocol.type);
  if (!info) {
    throw new UserError('В сохранённом конфиге клиента нет данных для восстановления');
  }

  if (protocol.type === 'awg2' || protocol.type === 'wireguard') {
    if (!info.clientIp || !info.presharedKey) {
      throw new UserError('В конфиге клиента нет адреса или preshared-key');
    }
    const peer = { clientPubKey: client.peer_id, presharedKey: info.presharedKey, clientIp: info.clientIp };
    if (protocol.type === 'awg2') await restoreAWG2Client(server, protocol, peer);
    else                          await restoreWireGuardClient(server, protocol, peer);
    return;
  }

  if (protocol.type === 'xray') {
    await restoreXrayClient(server, protocol, client.peer_id);
    return;
  }

  if (protocol.type === 'telemt') {
    if (!info.secret) throw new UserError('В ссылке клиента нет secret');
    await restoreTelemtClient(server, protocol, client.peer_id, info.secret);
  }
}

// Удаление строк, связанных с клиентом. Внешние ключи в базе выключены, поэтому
// ON DELETE CASCADE не сработает и связанное удаляем явно.
export function purgeClientRows(clientId: string): void {
  deleteSubscription(clientId);
  run('DELETE FROM client_stats WHERE client_id = ?', [clientId]);
  run('DELETE FROM clients WHERE id = ?', [clientId]);
}

async function saveImportedPeer(ctx: ClientContext): Promise<void> {
  const { client, protocol, server } = ctx;
  if (!protocol || !server || !client.peer_id) throw new UserError('Не хватает данных для приостановки клиента');
  if (client.peer_restore || extractPeerRestoreInfo(client.config ?? null, protocol.type)) return;

  assertContainerName(protocol.container_name);
  let info: PeerRestoreInfo | undefined;
  if (protocol.type === 'awg2' || protocol.type === 'wireguard') {
    const path = protocol.type === 'awg2' ? '/opt/amnezia/awg/awg0.conf' : '/opt/amnezia/wireguard/wg0.conf';
    const config = await readContainerFile(server, protocol.container_name, path);
    for (const block of config.split(/^\s*\[Peer\][ \t]*$/im).slice(1)) {
      const field = (key: string) => block.match(new RegExp(`^[ \\t]*${key}[ \\t]*=[ \\t]*([^\\r\\n#]+)`, 'im'))?.[1].trim();
      if (field('PublicKey') !== client.peer_id) continue;
      const allowed = field('AllowedIPs');
      const ip = allowed?.replace(/\/32$/, '');
      const psk = field('PresharedKey');
      const fields = [...block.matchAll(/^[ \t]*([A-Za-z]+)[ \t]*=/gm)].map(match => match[1].toLowerCase());
      const restorable = fields.every(key => ['publickey', 'allowedips', 'presharedkey'].includes(key));
      if (restorable && ip && allowed === `${ip}/32` && isIPv4(ip) && psk && /^[A-Za-z0-9+/]{43}=$/.test(psk)) {
        info = { clientIp: ip, presharedKey: psk };
      }
      break;
    }
  } else if (protocol.type === 'telemt') {
    const users = await readContainerFile(server, protocol.container_name, '/opt/amnezia/telemt/users');
    for (const line of users.split('\n')) {
      const match = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*"([0-9a-fA-F]{32})"\s*$/);
      if (match?.[1] === client.peer_id && /^c_[0-9a-f]{12}$/i.test(client.peer_id)) {
        info = { secret: match[2] };
        break;
      }
    }
  }
  if (!info) throw new UserError('Не удалось сохранить данные для восстановления импортированного клиента');
  run('UPDATE clients SET peer_restore = ? WHERE id = ?', [encrypt(JSON.stringify(info)), client.id]);
}

export async function suspendClient(client: Client): Promise<void> {
  const ctx = loadClientContext(client);
  await saveImportedPeer(ctx);
  await revokePeer(ctx);
  run('UPDATE clients SET suspended_at = ? WHERE id = ?', [Math.floor(Date.now() / 1000), client.id]);
}

export async function resumeClient(client: Client): Promise<void> {
  await restorePeer(loadClientContext(client));
  run('UPDATE clients SET suspended_at = NULL, peer_restore = NULL WHERE id = ?', [client.id]);
}
