// Общая механика WireGuard-подобных протоколов (WireGuard и AmneziaWG).
//
// Установка и выпуск клиента у них совпадали почти дословно: те же аргументы
// docker run, тот же порядок «собрать образ → запустить → сконфигурировать →
// перезапустить», та же выдача ключей и дописывание [Peer] в конфиг. Отличались
// только имя CLI (wg/awg), имя интерфейса и пути.
//
// Дублирование было не безобидным: правку per-protocol start.sh (f74fa36)
// применили к awg2 и xray, а WireGuard забыли — и он молча остался с чужим
// ENTRYPOINT, из-за чего wg0 не поднимался, а добавление клиента падало с
// "Unable to modify interface: No such device".

import { exec, execSudo } from '../ssh.js';
import { sh } from '../shell.js';
import { isIPv4 } from 'node:net';
import { randomUUID } from 'node:crypto';
import { query } from '../db.js';
import { decrypt } from '../crypto.js';
import { extractPeerRestoreInfo, type PeerRestoreInfo } from '../peerId.js';
import {
  writeRemoteFile, readRemoteFile, buildImage, assertPortFree, removePeerBlock, runContainer,
} from './common.js';
import { UserError } from '../errors.js';
import type { Server } from '../../types.js';

export interface WgFlavor {
  /** Имя CLI внутри контейнера. */
  tool: 'awg' | 'wg';
  /** Имя сетевого интерфейса (awg0 / wg0). */
  iface: string;
  /** Каталог с конфигами и ключами внутри /opt/amnezia. */
  confDir: string;
  containerName: string;
  imageName: string;
  buildDir: string;
  /** Как протокол называется в текстах ошибок. */
  label: string;
}

export const confPath = (f: WgFlavor): string => `${f.confDir}/${f.iface}.conf`;

// Аргументы docker run. Вынесены отдельно, чтобы проверка дрейфа могла
// пересчитать ожидаемый отпечаток для уже запущенного контейнера.
export function wgRunArgs(f: WgFlavor, port: number): string[] {
  return [
    `--log-driver json-file`,
    `--log-opt max-size=10m`,
    `--log-opt max-file=3`,
    `--restart always`,
    `--privileged`,
    `--cap-add=NET_ADMIN`,
    `--cap-add=SYS_MODULE`,
    `-p ${port}:${port}/udp`,
    `-v /lib/modules:/lib/modules`,
    `-v /opt/amnezia:/opt/amnezia`,
    `--sysctl="net.ipv4.conf.all.src_valid_mark=1"`,
    `--name ${f.containerName}`,
    f.imageName,
  ];
}

interface InstallArgs {
  port: number;
  subnetIp: string;
  subnetCidr: string;
  dockerfile: string;
  startScript: string;
  /**
   * Содержимое configure-скрипта целиком, вместе с export-ами. Может быть
   * функцией: AmneziaWG генерирует HeaderProtectionKey через `awg genkey`
   * ВНУТРИ контейнера, то есть уже после его запуска.
   */
  configureScript: string | (() => Promise<string>);
  /** Куда положить configure-скрипт (у протоколов разные имена файлов). */
  configurePath: string;
  /** Файл с публичным ключом сервера, который создаёт configure-скрипт. */
  serverPubKeyPath: string;
}

// Полный цикл установки. Возвращает публичный ключ сервера.
export async function installWgLike(server: Server, f: WgFlavor, args: InstallArgs): Promise<string> {
  // Освобождаем порт от своего старого контейнера (переустановка), затем проверяем,
  // что порт не занят кем-то ещё на хосте.
  await execSudo(server, `docker rm -f ${f.containerName} 2>/dev/null || true`);
  await assertPortFree(server, args.port, f.containerName);

  await buildImage(server, f.imageName, f.buildDir, args.dockerfile);

  await execSudo(server, `mkdir -p ${f.confDir}`);
  await writeRemoteFile(server, `${f.confDir}/start.sh`, args.startScript);
  await execSudo(server, `chmod +x ${f.confDir}/start.sh`);

  await runContainer(server, wgRunArgs(f, args.port));
  await execSudo(server, `docker network connect amnezia-dns-net ${f.containerName}`);

  const configureScript = typeof args.configureScript === 'string'
    ? args.configureScript
    : await args.configureScript();
  await writeRemoteFile(server, args.configurePath, configureScript);
  const configureRes = await execSudo(server, `docker exec ${f.containerName} bash ${args.configurePath}`);
  if (configureRes.code !== 0) {
    throw new UserError(`${f.label} configure script failed (exit ${configureRes.code}): ${configureRes.stderr || configureRes.stdout}`);
  }

  // start.sh поднимает интерфейс, только если конфиг существует на момент старта
  // контейнера. При установке конфиг создаётся configure-скриптом ПОСЛЕ старта,
  // поэтому интерфейс остаётся не поднятым (set падает с "No such device").
  // Перезапускаем — теперь start.sh найдёт конфиг и поднимет интерфейс.
  const restartRes = await execSudo(server, `docker restart ${f.containerName}`);
  if (restartRes.code !== 0) {
    throw new UserError(`Failed to restart ${f.label} container after configure: ${restartRes.stderr || restartRes.stdout}`);
  }

  const serverPubKey = await readRemoteFile(server, args.serverPubKeyPath);
  if (!serverPubKey) throw new UserError(`${f.label} configure script did not generate server public key`);
  return serverPubKey;
}

// Контейнер должен быть запущен — иначе любой set по интерфейсу бессмыслен.
export async function assertContainerRunning(server: Server, f: WgFlavor): Promise<void> {
  const statusRes = await exec(server, `docker inspect --format='{{.State.Status}}' ${f.containerName} 2>/dev/null || echo ''`);
  if (statusRes.stdout.trim() !== 'running') {
    throw new UserError(`${f.label} container '${f.containerName}' is not running. Start the protocol first.`);
  }
}

export interface PeerKeys { clientPrivKey: string; clientPubKey: string }

export async function genPeerKeys(server: Server, f: WgFlavor): Promise<PeerKeys> {
  const privRes = await execSudo(server, `docker exec ${f.containerName} ${f.tool} genkey`);
  if (privRes.code !== 0 || !privRes.stdout.trim()) {
    throw new UserError(`Failed to generate ${f.label} client private key: ${privRes.stderr || 'empty output'}`);
  }
  const clientPrivKey = privRes.stdout.trim();

  const pubRes = await execSudo(server, `echo '${clientPrivKey}' | docker exec -i ${f.containerName} ${f.tool} pubkey`);
  if (pubRes.code !== 0 || !pubRes.stdout.trim()) {
    throw new UserError(`Failed to generate ${f.label} client public key: ${pubRes.stderr || 'empty output'}`);
  }
  return { clientPrivKey, clientPubKey: pubRes.stdout.trim() };
}

// Учитываем адреса активных и приостановленных клиентов.
async function activePeerAddresses(server: Server, f: WgFlavor): Promise<string> {
  const result = await execSudo(server, `docker exec ${f.containerName} ${f.tool} show ${f.iface} allowed-ips`);
  if (result.code !== 0) throw new UserError(`Не удалось прочитать адреса пиров ${f.label}`);
  return result.stdout;
}

export async function nextClientIp(server: Server, f: WgFlavor, subnetPrefix: string, protocolId: string): Promise<string> {
  const addresses = new Set((await activePeerAddresses(server, f)).match(/\b\d+\.\d+\.\d+\.\d+(?=\/)/g) ?? []);
  const rows = query<{ config: string | null; peer_restore: string | null }>(
    'SELECT config, peer_restore FROM clients WHERE protocol_id = ?', [protocolId],
  );
  for (const row of rows) {
    const saved = decrypt(row.peer_restore);
    const info: PeerRestoreInfo | null = saved ? JSON.parse(saved) : extractPeerRestoreInfo(row.config, 'wireguard');
    if (info?.clientIp) addresses.add(info.clientIp);
  }
  for (let host = 2; host < 255; host++) {
    const candidate = `${subnetPrefix}.${host}`;
    if (!addresses.has(candidate)) return candidate;
  }
  throw new UserError(`В подсети ${f.label} закончились свободные адреса`);
}

async function readPeerConfig(server: Server, f: WgFlavor): Promise<string> {
  const result = await execSudo(server, `docker exec ${f.containerName} cat ${confPath(f)}`);
  if (result.code !== 0 || !result.stdout.trim()) throw new UserError(`Не удалось прочитать конфигурацию ${f.label}`);
  return result.stdout;
}

async function writePeerConfig(server: Server, f: WgFlavor, config: string): Promise<void> {
  const data = Buffer.from(config).toString('base64');
  const path = confPath(f);
  const tmp = `${path}.${randomUUID()}.tmp`;
  const write = `umask 077; base64 -d > ${tmp} && mv -f ${tmp} ${path}; status=$?; rm -f ${tmp}; exit $status`;
  const result = await execSudo(server, `printf '%s' '${data}' | docker exec -i ${f.containerName} sh -c ${sh(write)}`);
  if (result.code !== 0) throw new UserError(`Не удалось сохранить конфигурацию ${f.label}`);
}

const peerWrites = new Map<string, Promise<void>>();

async function updatePeers(server: Server, f: WgFlavor, update: () => Promise<void>): Promise<void> {
  const key = `${server.id}:${f.containerName}`;
  const next = (peerWrites.get(key) ?? Promise.resolve()).catch(() => {}).then(update);
  peerWrites.set(key, next);
  try {
    await next;
  } finally {
    if (peerWrites.get(key) === next) peerWrites.delete(key);
  }
}

// Добавляет пира в живой интерфейс и заменяет его блок [Peer] в конфиге.
export function addPeer(
  server: Server, f: WgFlavor,
  peer: { clientPubKey: string; presharedKey: string; clientIp: string },
): Promise<void> {
  return updatePeers(server, f, () => addPeerUnlocked(server, f, peer));
}

async function addPeerUnlocked(
  server: Server, f: WgFlavor,
  peer: { clientPubKey: string; presharedKey: string; clientIp: string },
): Promise<void> {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(peer.clientPubKey) || !isIPv4(peer.clientIp)) {
    throw new UserError(`Некорректный ключ или адрес пира ${f.label}`);
  }
  const address = `${peer.clientIp}/32`;
  const occupied = (await activePeerAddresses(server, f)).split('\n').some(line => {
    const [key, ...ips] = line.trim().split(/\s+/);
    return key !== peer.clientPubKey && ips.join(' ').split(/[,\s]+/).includes(address);
  });
  if (occupied) throw new UserError(`Адрес ${peer.clientIp} уже назначен другому пиру ${f.label}`);
  const conf = await readPeerConfig(server, f);
  const pskTmp = `/tmp/.psk_${randomUUID()}`;
  const pskB64 = Buffer.from(peer.presharedKey, 'utf8').toString('base64');
  const set = `umask 077; printf '%s' '${pskB64}' | base64 -d > ${pskTmp} &&
    ${f.tool} set ${f.iface} peer ${peer.clientPubKey} preshared-key ${pskTmp} allowed-ips ${address};
    status=$?; rm -f ${pskTmp}; exit $status`;
  const addPeerRes = await execSudo(server, `docker exec ${f.containerName} sh -c ${sh(set)}`);
  if (addPeerRes.code !== 0) {
    throw new UserError(`Failed to add ${f.label} peer: ${addPeerRes.stderr || addPeerRes.stdout}`);
  }

  const entry = `\n[Peer]\nPublicKey = ${peer.clientPubKey}\nPresharedKey = ${peer.presharedKey}\nAllowedIPs = ${address}\n`;
  await writePeerConfig(server, f, removePeerBlock(conf, peer.clientPubKey).trimEnd() + '\n' + entry);
}

// Отзыв клиента: убираем пира из живого интерфейса и из конфига (peerId = pubkey).
export function removePeer(server: Server, f: WgFlavor, peerId: string): Promise<void> {
  return updatePeers(server, f, async () => {
    const conf = await readPeerConfig(server, f);
    const result = await execSudo(server, `docker exec ${f.containerName} ${f.tool} set ${f.iface} peer ${sh(peerId)} remove`);
    if (result.code !== 0) throw new UserError(`Не удалось отключить пира ${f.label}`);
    const updated = removePeerBlock(conf, peerId);
    if (updated !== conf) await writePeerConfig(server, f, updated);
  });
}
