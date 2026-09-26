"use strict";

const crypto = require("crypto");
const forge = require("node-forge");

/* ==========================================================
   KEY PAIR / PEM HELPERS
   ========================================================== */

function generateKeyPair(bits = 2048) {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits }, (err, keys) => {
      if (err) return reject(err);
      resolve(keys);
    });
  });
}

const privateKeyToPem = (key) => forge.pki.privateKeyToPem(key);
const publicKeyToPem = (key) => forge.pki.publicKeyToPem(key);
const certToPem = (cert) => forge.pki.certificateToPem(cert);
const pemToPrivateKey = (pem) => forge.pki.privateKeyFromPem(pem);
const pemToCert = (pem) => forge.pki.certificateFromPem(pem);

function fingerprintOf(cert) {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const hex = forge.md.sha256.create().update(der).digest().toHex().toUpperCase();
  return hex.match(/.{1,2}/g).join(":");
}

/* ==========================================================
   ROOT CA GENERATION (self-signed, X.509 v3)
   ========================================================== */

async function createRootCA({ subject, days = 3650, bits = 4096 }) {
  const keys = await generateKeyPair(bits);

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + crypto.randomBytes(15).toString("hex").toUpperCase();
  cert.validity.notBefore = new Date(Date.now() - 5 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  const attrs = [
    { name: "commonName", value: subject.commonName },
    { name: "organizationName", value: subject.organization || "Let-S Secure" },
    { name: "organizationalUnitName", value: subject.ou || "Private CA" },
    { name: "countryName", value: subject.country || "IN" },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    {
      name: "keyUsage",
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
      critical: true,
    },
    { name: "subjectKeyIdentifier" },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    privateKeyPem: privateKeyToPem(keys.privateKey),
    certPem: certToPem(cert),
    serialNumber: cert.serialNumber.toUpperCase(),
    fingerprint: fingerprintOf(cert),
  };
}

/* ==========================================================
   LEAF CERTIFICATE ISSUANCE (signed by Root CA)
   ========================================================== */

async function issueCertificate({
  caPrivateKeyPem,
  caCertPem,
  subject,
  days = 365,
  keyBits = 2048,
}) {
  const caKey = pemToPrivateKey(caPrivateKeyPem);
  const caCert = pemToCert(caCertPem);

  const keys = await generateKeyPair(keyBits);

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString("hex").toUpperCase();
  cert.validity.notBefore = new Date(Date.now() - 5 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  const attrs = [
    { name: "commonName", value: subject.domain },
    { name: "organizationName", value: subject.project || "Let-S Secure Project" },
    { name: "organizationalUnitName", value: "Let-S Secure CA" },
    { name: "emailAddress", value: subject.email },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(caCert.subject.attributes);

  // SAN — include wildcard if base domain is bare
  const altNames = [{ type: 2, value: subject.domain }];
  if (!subject.domain.startsWith("*.")) {
    altNames.push({ type: 2, value: "*." + subject.domain });
  }

  cert.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    { name: "extKeyUsage", serverAuth: true, clientAuth: true },
    { name: "subjectAltName", altNames },
    { name: "subjectKeyIdentifier" },
    { name: "authorityKeyIdentifier", keyIdentifier: true },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  return {
    cert,
    certPem: certToPem(cert),
    privateKeyPem: privateKeyToPem(keys.privateKey),
    publicKeyPem: publicKeyToPem(keys.publicKey),
    serialNumber: cert.serialNumber.toUpperCase(),
    signature: forge.util.bytesToHex(cert.signature),
    fingerprint: fingerprintOf(cert),
  };
}

/* ==========================================================
   VERIFICATION
   ========================================================== */

function verifyCertificateSignature(certPem, caCertPem) {
  const leaf = pemToCert(certPem);
  const ca = pemToCert(caCertPem);
  return ca.verify(leaf);
}

/* ==========================================================
   AES-256-GCM ENCRYPTION (Root CA private key at rest)
   ========================================================== */

function encryptSecret(plaintext, masterKeyHex) {
  const key = Buffer.from(masterKeyHex, "hex");
  if (key.length !== 32) {
    throw new Error("MASTER_ENCRYPTION_KEY must be 32 bytes (64 hex chars)");
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: enc.toString("base64"),
    alg: "aes-256-gcm",
  };
}

function decryptSecret(payload, masterKeyHex) {
  const key = Buffer.from(masterKeyHex, "hex");
  if (key.length !== 32) {
    throw new Error("MASTER_ENCRYPTION_KEY must be 32 bytes (64 hex chars)");
  }
  const iv = Buffer.from(payload.iv, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const data = Buffer.from(payload.data, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

/* ==========================================================
   PASSWORD HASHING (scrypt, no external dependency)
   ========================================================== */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [scheme, salt, hash] = String(stored || "").split("$");
    if (scheme !== "scrypt" || !salt || !hash) return false;
    const test = crypto.scryptSync(password, salt, 64).toString("hex");
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(test, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

module.exports = {
  generateKeyPair,
  privateKeyToPem,
  publicKeyToPem,
  certToPem,
  pemToPrivateKey,
  pemToCert,
  createRootCA,
  issueCertificate,
  verifyCertificateSignature,
  encryptSecret,
  decryptSecret,
  hashPassword,
  verifyPassword,
};
