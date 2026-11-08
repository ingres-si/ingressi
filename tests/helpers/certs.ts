import forge from 'node-forge';

export interface GeneratedCertificate {
  certificatePem: string;
  privateKeyPem: string;
}

export interface Pkcs12Identity {
  certificatePem: string;
  privateKeyPem: string;
}

function randomSerialNumber(): string {
  const bytes = forge.random.getBytesSync(16).split('');
  const firstByte = bytes[0]?.charCodeAt(0) ?? 1;
  bytes[0] = String.fromCharCode(firstByte & 0x7f || 1);
  return forge.util.bytesToHex(bytes.join(''));
}

export function createSelfSignedServerCertificate(
  commonName: string,
  altNames: string[],
  validityDays = 30
): GeneratedCertificate {
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  const cert = forge.pki.createCertificate();

  cert.publicKey = keypair.publicKey;
  cert.serialNumber = randomSerialNumber();
  cert.validity.notBefore = new Date();
  // Exactly validityDays from now: calendar arithmetic (setDate) is a day plus
  // or minus an hour when the window crosses a daylight saving change.
  cert.validity.notAfter = new Date(cert.validity.notBefore.getTime() + validityDays * 24 * 60 * 60 * 1000);

  const subject = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'Ingressi E2E' },
  ];

  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: altNames.map((value) => ({ type: 2, value })),
    },
  ]);

  cert.sign(keypair.privateKey, forge.md.sha256.create());

  return {
    certificatePem: forge.pki.certificateToPem(cert),
    privateKeyPem: forge.pki.privateKeyToPem(keypair.privateKey),
  };
}

export function parsePkcs12Identity(bundle: Buffer, password: string): Pkcs12Identity {
  const der = forge.util.createBuffer(bundle.toString('binary'));
  const p12Asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

  const keyBags = p12.getBags({
    bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
  })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? [];
  const key = keyBags[0]?.key;
  if (!key) {
    throw new Error('PKCS#12 bundle did not contain a private key');
  }

  const certBags = p12.getBags({
    bagType: forge.pki.oids.certBag,
  })[forge.pki.oids.certBag] ?? [];
  const certBag = certBags.find((bag) => {
    const extKeyUsage = bag.cert?.getExtension('extKeyUsage');
    const basicConstraints = bag.cert?.getExtension('basicConstraints');
    const isClientCert = Boolean(extKeyUsage && 'clientAuth' in extKeyUsage && extKeyUsage.clientAuth);
    const isCa = Boolean(basicConstraints && 'cA' in basicConstraints && basicConstraints.cA);
    return isClientCert || !isCa;
  }) ?? certBags[0];

  if (!certBag?.cert) {
    throw new Error('PKCS#12 bundle did not contain a certificate');
  }

  return {
    certificatePem: forge.pki.certificateToPem(certBag.cert),
    privateKeyPem: forge.pki.privateKeyToPem(key),
  };
}

export interface ExternalCa {
  certificatePem: string;
  privateKeyPem: string;
}

/**
 * A certificate authority that Ingressi never sees the key of, like Cloudflare's
 * origin pull CA: import `certificatePem`, sign client certificates with `issueExternalClientCertificate`.
 */
export function createExternalCa(commonName: string, validityDays = 30): ExternalCa {
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keypair.publicKey;
  cert.serialNumber = randomSerialNumber();
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000);
  const subject = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'Ingressi E2E External CA' },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
  ]);
  cert.sign(keypair.privateKey, forge.md.sha256.create());
  return { certificatePem: forge.pki.certificateToPem(cert), privateKeyPem: forge.pki.privateKeyToPem(keypair.privateKey) };
}

export function issueExternalClientCertificate(
  ca: ExternalCa,
  commonName: string,
  options: { validityDays?: number; expired?: boolean } = {}
): Pkcs12Identity {
  const caCert = forge.pki.certificateFromPem(ca.certificatePem);
  const caKey = forge.pki.privateKeyFromPem(ca.privateKeyPem);
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keypair.publicKey;
  cert.serialNumber = randomSerialNumber();
  const now = Date.now();
  cert.validity.notBefore = new Date(now - (options.expired ? 3 * 24 * 3600_000 : 60_000));
  cert.validity.notAfter = new Date(options.expired ? now - 24 * 3600_000 : now + (options.validityDays ?? 30) * 24 * 3600_000);
  cert.setSubject([{ name: 'commonName', value: commonName }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, critical: true },
    { name: 'extKeyUsage', clientAuth: true },
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  return { certificatePem: forge.pki.certificateToPem(cert), privateKeyPem: forge.pki.privateKeyToPem(keypair.privateKey) };
}
