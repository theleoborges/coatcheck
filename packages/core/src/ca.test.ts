import { describe, it, expect, afterEach } from 'vitest';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import type { AddressInfo } from 'node:net';
import { CertAuthority } from './ca.js';

const tmpDirs: string[] = [];
function tmpDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'coatcheck-ca-'));
  tmpDirs.push(d);
  return d;
}

afterEach(() => {
  for (const d of tmpDirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe('CertAuthority', () => {
  it('generates an ECDSA P-256 CA certificate', async () => {
    const ca = await CertAuthority.create();
    const cert = new X509Certificate(ca.caCertPem);
    expect(cert.ca).toBe(true);
    expect(cert.subject).toContain('CN=coatcheck CA');
    expect(cert.publicKey.asymmetricKeyType).toBe('ec');
    expect(cert.publicKey.asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    expect(cert.verify(cert.publicKey)).toBe(true);
  });

  it('uses a configured subject', async () => {
    const ca = await CertAuthority.create({ subject: 'CN=Example Broker CA, O=Example' });
    expect(new X509Certificate(ca.caCertPem).subject).toContain('CN=Example Broker CA');
  });

  it('mints a leaf for a DNS name that chains to the CA', async () => {
    const ca = await CertAuthority.create();
    const caCert = new X509Certificate(ca.caCertPem);
    const { cert } = await ca.getCertForHost('api.example.com');
    const leaf = new X509Certificate(cert);

    expect(leaf.ca).toBe(false);
    expect(leaf.checkIssued(caCert)).toBe(true);
    expect(leaf.verify(caCert.publicKey)).toBe(true);
    expect(leaf.subjectAltName).toBe('DNS:api.example.com');
    expect(leaf.checkHost('api.example.com')).toBe('api.example.com');
    expect(leaf.checkHost('other.example.com')).toBeUndefined();
    expect(leaf.keyUsage).toEqual(['1.3.6.1.5.5.7.3.1']); // EKU serverAuth
    expect(new Date(leaf.validTo).getTime()).toBeLessThanOrEqual(new Date(caCert.validTo).getTime());
  });

  it('puts IP targets in an IP SAN', async () => {
    const ca = await CertAuthority.create();
    const v4 = new X509Certificate((await ca.getCertForHost('127.0.0.1')).cert);
    expect(v4.subjectAltName).toBe('IP Address:127.0.0.1');
    expect(v4.checkIP('127.0.0.1')).toBe('127.0.0.1');
    const v6 = new X509Certificate((await ca.getCertForHost('::1')).cert);
    expect(v6.checkIP('::1')).toBe('::1');
  });

  it('completes a real TLS handshake trusted only via the CA', async () => {
    const ca = await CertAuthority.create();
    const leaf = await ca.getCertForHost('localhost');
    const server = tls.createServer({ key: leaf.key, cert: leaf.cert }, s => s.end('ok'));
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    try {
      const body = await new Promise<string>((resolve, reject) => {
        const sock = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: ca.caCertPem }, () => {
          expect(sock.authorized).toBe(true);
        });
        let data = '';
        sock.on('data', d => { data += d; });
        sock.on('end', () => resolve(data));
        sock.on('error', reject);
      });
      expect(body).toBe('ok');
    } finally {
      server.close();
    }
  });

  it('caches leaf certs and evicts least-recently-used beyond the cap', async () => {
    const ca = await CertAuthority.create({ leafCacheSize: 2 });
    const a1 = await ca.getCertForHost('a.example.com');
    expect(await ca.getCertForHost('a.example.com')).toBe(a1);
    await ca.getCertForHost('b.example.com');
    await ca.getCertForHost('a.example.com'); // a is now most recent
    await ca.getCertForHost('c.example.com'); // evicts b
    expect(ca.cachedLeafCount).toBe(2);
    expect(await ca.getCertForHost('a.example.com')).toBe(a1);
    const b2 = await ca.getCertForHost('b.example.com');
    expect(b2.cert).not.toBe(a1.cert);
  });

  it('refuses hostnames with shell metacharacters or path segments (no shell, no files)', async () => {
    const dir = tmpDir();
    const marker = path.join(dir, 'pwned');
    const ca = await CertAuthority.create({ dir });
    const attacks = [
      `$(touch ${marker}).com`,
      `\`touch ${marker}\`.com`,
      `a.com;touch ${marker}`,
      '../../etc/evil',
      'a/b.com',
    ];
    for (const host of attacks) {
      await expect(ca.getCertForHost(host), host).rejects.toThrow('invalid hostname');
    }
    expect(fs.existsSync(marker)).toBe(false);
    expect(fs.readdirSync(dir).sort()).toEqual(['ca.crt', 'ca.key']);
  });

  it('persists only the CA (key mode 0600) and reloads it', async () => {
    const dir = tmpDir();
    const ca1 = await CertAuthority.create({ dir });
    await ca1.getCertForHost('api.example.com');
    expect(fs.readdirSync(dir).sort()).toEqual(['ca.crt', 'ca.key']);
    if (process.platform !== 'win32') {
      expect(fs.statSync(path.join(dir, 'ca.key')).mode & 0o777).toBe(0o600);
    }

    const ca2 = await CertAuthority.create({ dir });
    expect(ca2.caCertPem).toBe(ca1.caCertPem);
    const leaf = new X509Certificate((await ca2.getCertForHost('api.example.com')).cert);
    expect(leaf.verify(new X509Certificate(ca1.caCertPem).publicKey)).toBe(true);
  });

  it('refuses a persisted RSA CA', async () => {
    const dir = tmpDir();
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    fs.writeFileSync(path.join(dir, 'ca.key'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
    fs.writeFileSync(path.join(dir, 'ca.crt'), 'not used');
    await expect(CertAuthority.create({ dir })).rejects.toThrow(/requires an ECDSA P-256 CA/);
  });

  it('works with an in-memory CA when no directory is configured', async () => {
    const ca = await CertAuthority.create();
    expect(ca.caCertPem).toMatch(/^-----BEGIN CERTIFICATE-----/);
  });
});
