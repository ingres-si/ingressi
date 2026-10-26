/**
 * Requests to Caddy that open with a PROXY protocol header, as a TCP load
 * balancer in front of Caddy sends them (HAProxy `send-proxy` /
 * `send-proxy-v2`, a cloud network load balancer, Caddy's layer4 proxy).
 *
 * The header is written on the TCP connection before anything else: before
 * the HTTP request on port 80, before the TLS handshake on port 443.
 * Specification: https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt
 */
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

export interface ProxiedResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** The 12-byte signature every v2 header starts with. */
const V2_SIGNATURE = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);

/** The 16 bytes of an IPv6 address. */
function ipv6Bytes(address: string): Buffer {
  const [head, tail] = address.split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail ? tail.split(':') : [];
  const zeros = tail === undefined ? 0 : 8 - headGroups.length - tailGroups.length;
  const groups = [...headGroups, ...Array<string>(zeros).fill('0'), ...tailGroups];
  if (groups.length !== 8) throw new Error(`Not an IPv6 address: ${address}`);
  const bytes = Buffer.alloc(16);
  groups.forEach((group, index) => bytes.writeUInt16BE(parseInt(group || '0', 16), index * 2));
  return bytes;
}

function ipv4Bytes(address: string): Buffer {
  return Buffer.from(address.split('.').map(Number));
}

/** A v1 (text) header for a TCP connection from `source`; TCP4 or TCP6 by the address. */
export function proxyV1(source: string, { sourcePort = 41234, destination, destinationPort = 80 }: { sourcePort?: number; destination?: string; destinationPort?: number } = {}): Buffer {
  const family = net.isIPv6(source) ? 'TCP6' : 'TCP4';
  const to = destination ?? (family === 'TCP6' ? '2001:db8::80' : '192.0.2.80');
  return Buffer.from(`PROXY ${family} ${source} ${to} ${sourcePort} ${destinationPort}\r\n`, 'latin1');
}

/** The v1 header for a connection whose client the balancer does not know. */
export function proxyV1Unknown(): Buffer {
  return Buffer.from('PROXY UNKNOWN\r\n', 'latin1');
}

/**
 * A v2 (binary) PROXY header for a TCP connection from `source`, IPv4 or
 * IPv6 by the address, with optional TLVs (type, value) after the addresses.
 */
export function proxyV2(
  source: string,
  {
    sourcePort = 41234,
    destination,
    destinationPort = 80,
    tlvs = [],
  }: { sourcePort?: number; destination?: string; destinationPort?: number; tlvs?: Array<[number, Buffer]> } = {}
): Buffer {
  const v6 = net.isIPv6(source);
  const to = destination ?? (v6 ? '2001:db8::80' : '192.0.2.80');
  const addresses = v6 ? Buffer.concat([ipv6Bytes(source), ipv6Bytes(to)]) : Buffer.concat([ipv4Bytes(source), ipv4Bytes(to)]);
  const ports = Buffer.alloc(4);
  ports.writeUInt16BE(sourcePort, 0);
  ports.writeUInt16BE(destinationPort, 2);
  const extra = Buffer.concat(
    tlvs.map(([type, value]) => {
      const head = Buffer.alloc(3);
      head.writeUInt8(type, 0);
      head.writeUInt16BE(value.length, 1);
      return Buffer.concat([head, value]);
    })
  );
  const body = Buffer.concat([addresses, ports, extra]);
  const head = Buffer.alloc(4);
  head.writeUInt8(0x21, 0); // version 2, PROXY
  head.writeUInt8(v6 ? 0x21 : 0x11, 1); // AF_INET6 or AF_INET, STREAM
  head.writeUInt16BE(body.length, 2);
  return Buffer.concat([V2_SIGNATURE, head, body]);
}

/** The v2 LOCAL header a balancer sends for its own connections (health checks): no address. */
export function proxyV2Local(): Buffer {
  return Buffer.concat([V2_SIGNATURE, Buffer.from([0x20, 0x00, 0x00, 0x00])]);
}

/** A TCP connection to Caddy that has sent `header` (nothing when null) before anything else. */
function connect(port: number, header: Buffer | null): net.Socket {
  const socket = net.connect({ host: '127.0.0.1', port });
  if (header) socket.write(header);
  return socket;
}

function collect(res: http.IncomingMessage, resolve: (response: ProxiedResponse) => void): void {
  let body = '';
  res.setEncoding('utf8');
  res.on('data', (chunk: string) => { body += chunk; });
  res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
}

/** GET http://<domain><path> through Caddy's port 80, the connection opening with `header`. */
export function proxiedHttpGet(
  domain: string,
  header: Buffer | null,
  path = '/',
  extraHeaders: Record<string, string> = {}
): Promise<ProxiedResponse> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: 80,
        path,
        method: 'GET',
        headers: { Host: domain, Connection: 'close', ...extraHeaders },
        createConnection: () => connect(80, header),
      },
      (res) => collect(res, resolve)
    );
    req.setTimeout(15_000, () => req.destroy(new Error(`Request to ${domain}${path} timed out`)));
    req.on('error', reject);
    req.end();
  });
}

/**
 * GET https://<domain><path> through Caddy's port 443: the PROXY header
 * first, then the TLS handshake. The certificate Caddy serves is verified
 * against `ca`, the PEM the test gave Caddy for the domain.
 */
export function proxiedHttpsGet(
  domain: string,
  header: Buffer | null,
  ca: string,
  path = '/',
  extraHeaders: Record<string, string> = {}
): Promise<ProxiedResponse> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port: 443,
        path,
        method: 'GET',
        headers: { Host: domain, Connection: 'close', ...extraHeaders },
        servername: domain,
        ca,
        createConnection: () => tls.connect({ socket: connect(443, header), servername: domain, ca, ALPNProtocols: ['http/1.1'] }),
      },
      (res) => collect(res, resolve)
    );
    req.setTimeout(15_000, () => req.destroy(new Error(`Request to https://${domain}${path} timed out`)));
    req.on('error', reject);
    req.end();
  });
}

/**
 * Several GETs on one kept-alive connection to port 80 that sent `header`
 * once, at its start: every request on it comes from the header's address.
 */
export async function proxiedKeepAliveGets(domain: string, header: Buffer, paths: string[]): Promise<ProxiedResponse[]> {
  let connections = 0;
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  // The agent asks for a connection only when it has none to reuse.
  (agent as unknown as { createConnection: () => net.Socket }).createConnection = () => {
    connections += 1;
    return connect(80, header);
  };
  try {
    const responses: ProxiedResponse[] = [];
    for (const path of paths) {
      responses.push(
        await new Promise<ProxiedResponse>((resolve, reject) => {
          const req = http.request({ host: '127.0.0.1', port: 80, path, method: 'GET', headers: { Host: domain }, agent }, (res) => collect(res, resolve));
          req.setTimeout(15_000, () => req.destroy(new Error(`Request to ${domain}${path} timed out`)));
          req.on('error', reject);
          req.end();
        })
      );
    }
    if (connections !== 1) throw new Error(`Expected one connection for ${paths.length} requests, the agent opened ${connections}`);
    return responses;
  } finally {
    agent.destroy();
  }
}

/**
 * Writes `chunks` to port 80 one after another, `delayMs` apart, then reads
 * until Caddy closes the connection (or `timeoutMs` passes) and returns the
 * raw answer, latin1. For headers split over several packets and for bytes
 * Caddy must refuse.
 */
export function rawExchange(chunks: Buffer[], { delayMs = 50, timeoutMs = 10_000, port = 80 } = {}): Promise<{ raw: string; closed: boolean }> {
  return new Promise((resolve) => {
    let raw = '';
    let settled = false;
    const socket = net.connect({ host: '127.0.0.1', port });
    const finish = (closed: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ raw, closed });
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    socket.on('data', (data) => { raw += data.toString('latin1'); });
    socket.on('end', () => finish(true));
    socket.on('close', () => finish(true));
    socket.on('error', () => finish(true));
    socket.on('connect', async () => {
      for (const [index, chunk] of chunks.entries()) {
        if (index > 0) await new Promise((r) => setTimeout(r, delayMs));
        if (socket.destroyed) return;
        socket.write(chunk);
      }
    });
  });
}

/** A plain HTTP/1.1 GET with Connection: close, as bytes. */
export function httpRequestBytes(domain: string, path = '/', extraHeaders: Record<string, string> = {}): Buffer {
  const lines = [`GET ${path} HTTP/1.1`, `Host: ${domain}`, 'Connection: close', ...Object.entries(extraHeaders).map(([name, value]) => `${name}: ${value}`)];
  return Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1');
}

/** The client address Caddy passed upstream, from the request a traefik/whoami upstream echoes back. */
export function forwardedFor(body: string): string | null {
  return body.match(/^X-Forwarded-For: (.+)$/im)?.[1]?.trim() ?? null;
}
