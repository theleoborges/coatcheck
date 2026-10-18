import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createPrivateKey, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { isValidHostname } from './connect-target.js';

x509.cryptoProvider.set(crypto);

const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGNING_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' } as const;
const DEFAULT_SUBJECT = 'CN=coatcheck CA, O=coatcheck';
const CA_VALIDITY_DAYS = 365;
const LEAF_VALIDITY_DAYS = 30;
const CLOCK_SKEW_MS = 60 * 60 * 1000;
const DEFAULT_LEAF_CACHE_SIZE = 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface HostCert {
  key: string;
  cert: string;
}

export interface CertAuthorityOptions {
  /** Persist the CA key and cert here. Unset: the CA lives in memory only. Leaf certs are never written. */
  dir?: string;
  /** Distinguished name of the CA certificate. */
  subject?: string;
  /** Max leaf certs kept in memory (LRU). */
  leafCacheSize?: number;
}

/**
 * Self-signed Certificate Authority for MITM TLS interception, generated
 * in-process (WebCrypto, ECDSA P-256). Per-host leaf certificates are minted on
 * demand and cached in memory only. The root CA cert must be trusted by the agent.
 */
export class CertAuthority {
  private hostCerts = new Map<string, Promise<HostCert>>();

  private constructor(
    private readonly caKey: CryptoKey,
    private readonly caCert: x509.X509Certificate,
    private readonly leafCacheSize: number,
  ) {}

  static async create(opts: CertAuthorityOptions = {}): Promise<CertAuthority> {
    const leafCacheSize = opts.leafCacheSize ?? DEFAULT_LEAF_CACHE_SIZE;
    const subject = opts.subject ?? DEFAULT_SUBJECT;

    if (!opts.dir) {
      const { key, cert } = await generateCa(subject);
      console.log('Generated new in-memory CA certificate');
      return new CertAuthority(key, cert, leafCacheSize);
    }

    fs.mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
    const keyPath = path.join(opts.dir, 'ca.key');
    const certPath = path.join(opts.dir, 'ca.crt');

    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
      const key = await importCaKey(fs.readFileSync(keyPath, 'utf8'), keyPath);
      const cert = new x509.X509Certificate(fs.readFileSync(certPath, 'utf8'));
      console.log('Loaded existing CA certificate');
      return new CertAuthority(key, cert, leafCacheSize);
    }

    const { key, cert } = await generateCa(subject);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
    fs.writeFileSync(keyPath, x509.PemConverter.encode(pkcs8, 'PRIVATE KEY'), { mode: 0o600 });
    fs.writeFileSync(certPath, cert.toString('pem'));
    console.log('Generated new CA certificate');
    return new CertAuthority(key, cert, leafCacheSize);
  }

  /** Get the CA certificate (for agent container to trust) */
  get caCertPem(): string {
    return this.caCert.toString('pem');
  }

  /** Mint (or return cached) a TLS certificate for a DNS name or IP literal. */
  getCertForHost(hostname: string): Promise<HostCert> {
    // Defence in depth: callers validate CONNECT targets, but the CA refuses
    // anything that is not a plain hostname or IP literal regardless.
    if (!isValidHostname(hostname)) {
      return Promise.reject(new Error('invalid hostname for certificate'));
    }

    const cached = this.hostCerts.get(hostname);
    if (cached) {
      // Refresh LRU position.
      this.hostCerts.delete(hostname);
      this.hostCerts.set(hostname, cached);
      return cached;
    }

    const pending = this.mintLeaf(hostname);
    this.hostCerts.set(hostname, pending);
    pending.catch(() => this.hostCerts.delete(hostname));
    while (this.hostCerts.size > this.leafCacheSize) {
      const oldest = this.hostCerts.keys().next().value as string;
      this.hostCerts.delete(oldest);
    }
    return pending;
  }

  /** Number of leaf certs currently cached. */
  get cachedLeafCount(): number {
    return this.hostCerts.size;
  }

  private async mintLeaf(hostname: string): Promise<HostCert> {
    const keys = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ['sign', 'verify']) as CryptoKeyPair;
    const now = Date.now();
    const notAfter = Math.min(now + LEAF_VALIDITY_DAYS * DAY_MS, this.caCert.notAfter.getTime());
    const isIp = net.isIP(hostname) !== 0;

    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serialNumber(),
      subject: [{ CN: [hostname] }],
      issuer: this.caCert.subject,
      notBefore: new Date(now - CLOCK_SKEW_MS),
      notAfter: new Date(notAfter),
      signingAlgorithm: SIGNING_ALGORITHM,
      publicKey: keys.publicKey,
      signingKey: this.caKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
        new x509.SubjectAlternativeNameExtension([{ type: isIp ? 'ip' : 'dns', value: hostname }]),
        await x509.AuthorityKeyIdentifierExtension.create(this.caCert),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    });

    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keys.privateKey);
    return {
      key: x509.PemConverter.encode(pkcs8, 'PRIVATE KEY'),
      cert: cert.toString('pem'),
    };
  }
}

async function generateCa(subject: string): Promise<{ key: CryptoKey; cert: x509.X509Certificate }> {
  const keys = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ['sign', 'verify']) as CryptoKeyPair;
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serialNumber(),
    name: subject,
    notBefore: new Date(now - CLOCK_SKEW_MS),
    notAfter: new Date(now + CA_VALIDITY_DAYS * DAY_MS),
    signingAlgorithm: SIGNING_ALGORITHM,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  return { key: keys.privateKey, cert };
}

/** Import a persisted CA key. Only ECDSA P-256 is supported; anything else fails startup. */
async function importCaKey(pem: string, keyPath: string): Promise<CryptoKey> {
  let details: { type?: string; curve?: string };
  try {
    const key = createPrivateKey(pem);
    details = { type: key.asymmetricKeyType, curve: key.asymmetricKeyDetails?.namedCurve };
  } catch {
    details = {};
  }
  if (details.type !== 'ec' || details.curve !== 'prime256v1') {
    throw new Error(
      `Unsupported CA key at ${keyPath}: coatcheck requires an ECDSA P-256 CA. ` +
      'Delete ca.key and ca.crt in the CA directory to generate a new CA, then re-distribute /_ca to agents.',
    );
  }
  const der = createPrivateKey(pem).export({ type: 'pkcs8', format: 'der' });
  return crypto.subtle.importKey('pkcs8', der, KEY_ALGORITHM, false, ['sign']);
}

/** Random positive 128-bit serial number (hex). */
function serialNumber(): string {
  const bytes = randomBytes(16);
  bytes[0] &= 0x7f;
  return bytes.toString('hex');
}
