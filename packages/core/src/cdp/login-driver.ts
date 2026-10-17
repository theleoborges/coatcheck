import type { CdpConnection } from './proxy.js';
import type { LoginRequest, LoginResult } from '../cdp-session-store.js';

/**
 * Broker-performed login driver (design: docs/design/cdp-broker-login.md).
 * Full implementation lands with the `/login` route; this placeholder keeps the
 * controller surface wired while the per-connection machinery is built out.
 */
export async function runLogin(_conn: CdpConnection, _req: LoginRequest): Promise<LoginResult> {
  await Promise.resolve();
  return { status: 502, reason: 'driver-error' };
}
