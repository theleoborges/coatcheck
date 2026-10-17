import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const CA_DIR = process.env.CA_DIR ?? '/tmp/proxy-ca';

interface HostCert {
  key: string;
  cert: string;
}

/**
 * Self-signed Certificate Authority for MITM TLS interception.
 * Generates a root CA on startup and per-host certificates on demand.
 * The root CA cert should be trusted by the agent container.
 */
export class CertAuthority {
  private caKey: string;
  private caCert: string;
  private hostCerts = new Map<string, HostCert>();

  constructor() {
    fs.mkdirSync(CA_DIR, { recursive: true });

    const caKeyPath = path.join(CA_DIR, 'ca.key');
    const caCertPath = path.join(CA_DIR, 'ca.crt');

    if (fs.existsSync(caKeyPath) && fs.existsSync(caCertPath)) {
      // Reuse existing CA (persisted across restarts if CA_DIR is mounted)
      this.caKey = fs.readFileSync(caKeyPath, 'utf8');
      this.caCert = fs.readFileSync(caCertPath, 'utf8');
      console.log('Loaded existing CA certificate');
    } else {
      // Generate new CA
      execSync(`openssl genrsa -out ${caKeyPath} 2048 2>/dev/null`);
      execSync(
        `openssl req -new -x509 -key ${caKeyPath} -out ${caCertPath} -days 365 ` +
        `-subj "/CN=coatcheck CA/O=coatcheck" 2>/dev/null`
      );
      this.caKey = fs.readFileSync(caKeyPath, 'utf8');
      this.caCert = fs.readFileSync(caCertPath, 'utf8');
      console.log('Generated new CA certificate');
    }
  }

  /** Get the CA certificate (for agent container to trust) */
  get caCertPem(): string {
    return this.caCert;
  }

  /** Get the CA certificate file path */
  get caCertPath(): string {
    return path.join(CA_DIR, 'ca.crt');
  }

  /** Generate (or return cached) a TLS certificate for a specific hostname */
  getCertForHost(hostname: string): HostCert {
    const cached = this.hostCerts.get(hostname);
    if (cached) return cached;

    const hostKeyPath = path.join(CA_DIR, `${hostname}.key`);
    const hostCsrPath = path.join(CA_DIR, `${hostname}.csr`);
    const hostCertPath = path.join(CA_DIR, `${hostname}.crt`);
    const extPath = path.join(CA_DIR, `${hostname}.ext`);

    // Generate host key
    execSync(`openssl genrsa -out ${hostKeyPath} 2048 2>/dev/null`);

    // Generate CSR
    execSync(
      `openssl req -new -key ${hostKeyPath} -out ${hostCsrPath} ` +
      `-subj "/CN=${hostname}" 2>/dev/null`
    );

    // Create extension file for SAN
    fs.writeFileSync(extPath,
      `subjectAltName=DNS:${hostname}\n` +
      `basicConstraints=CA:FALSE\n` +
      `keyUsage=digitalSignature,keyEncipherment\n` +
      `extendedKeyUsage=serverAuth\n`
    );

    // Sign with CA
    execSync(
      `openssl x509 -req -in ${hostCsrPath} -CA ${path.join(CA_DIR, 'ca.crt')} ` +
      `-CAkey ${path.join(CA_DIR, 'ca.key')} -CAcreateserial ` +
      `-out ${hostCertPath} -days 30 -extfile ${extPath} 2>/dev/null`
    );

    const hostCert: HostCert = {
      key: fs.readFileSync(hostKeyPath, 'utf8'),
      cert: fs.readFileSync(hostCertPath, 'utf8'),
    };

    this.hostCerts.set(hostname, hostCert);

    // Clean up temp files
    try {
      fs.unlinkSync(hostCsrPath);
      fs.unlinkSync(extPath);
    } catch { /* ignore */ }

    return hostCert;
  }
}
