/**
 * Low-level TCP and UDP helpers for L4 proxy functional tests.
 *
 * Sends raw TCP connections and UDP datagrams to Caddy's L4 proxy ports
 * and reads responses.
 *
 * Default read timeout is generous (10 s) because the echo backends used in
 * the compose test stack are linux/amd64 images that run under emulation on
 * Apple Silicon hosts and can be slow to produce their banner under load.
 */
import net from 'node:net';
import dgram from 'node:dgram';

export interface TcpResponse {
  data: string;
  connected: boolean;
}

/**
 * Open a TCP connection to the given host:port, send a payload,
 * and collect whatever comes back within the timeout window.
 */
export function tcpSend(
  host: string,
  port: number,
  payload: string,
  timeoutMs = 10_000
): Promise<TcpResponse> {
  return new Promise((resolve, reject) => {
    let data = '';
    let connected = false;
    const socket = net.createConnection({ host, port }, () => {
      connected = true;
      socket.write(payload);
    });

    socket.setTimeout(timeoutMs);

    socket.on('data', (chunk) => {
      data += chunk.toString();
    });

    socket.on('end', () => {
      resolve({ data, connected });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ data, connected });
    });

    socket.on('error', (err) => {
      if (connected) {
        resolve({ data, connected });
      } else {
        reject(err);
      }
    });
  });
}

/**
 * Test if a TCP port is accepting connections.
 */
export function tcpConnect(
  host: string,
  port: number,
  timeoutMs = 5_000
): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      resolve(false);
    });
  });
}

/**
 * Poll until a TCP port accepts connections.
 * Similar to waitForRoute() but for TCP.
 */
export async function waitForTcpRoute(
  host: string,
  port: number,
  timeoutMs = 15_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await tcpConnect(host, port, 2000);
    if (ok) return;
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`TCP port ${host}:${port} not ready after ${timeoutMs}ms`);
}

/**
 * Poll until data sent to a TCP port comes back, that is until Caddy proxies
 * the port to an echo upstream. waitForTcpRoute only waits for the port to
 * accept connections, which Docker's port forwarding does whether or not
 * Caddy listens behind it: after a change made through the dashboard, or a
 * restart of the Caddy container, wait with this one before sending the
 * traffic a test asserts on.
 */
export async function waitForTcpEcho(host: string, port: number, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const probe = 'echo-ready-probe';
  while (Date.now() < deadline) {
    try {
      const res = await tcpSend(host, port, `${probe}\n`, 1_000);
      if (res.data.includes(probe)) return;
    } catch {
      // not accepting connections yet
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`TCP port ${host}:${port} did not echo within ${timeoutMs}ms`);
}

// ---------------------------------------------------------------------------
// UDP helpers
// ---------------------------------------------------------------------------

export interface UdpResponse {
  data: string;
  received: boolean;
}

/**
 * Send a UDP datagram and wait for a response.
 */
export function udpSend(
  host: string,
  port: number,
  payload: string,
  timeoutMs = 5_000
): Promise<UdpResponse> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let received = false;
    let data = '';

    const timer = setTimeout(() => {
      socket.close();
      resolve({ data, received });
    }, timeoutMs);

    socket.on('message', (msg) => {
      received = true;
      data += msg.toString();
      clearTimeout(timer);
      socket.close();
      resolve({ data, received });
    });

    socket.on('error', () => {
      clearTimeout(timer);
      socket.close();
      resolve({ data, received });
    });

    socket.send(payload, port, host);
  });
}

/**
 * Poll until a UDP port responds to a test datagram.
 */
export async function waitForUdpRoute(
  host: string,
  port: number,
  timeoutMs = 15_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await udpSend(host, port, 'ping', 2000);
    if (res.received) return;
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`UDP port ${host}:${port} not ready after ${timeoutMs}ms`);
}
