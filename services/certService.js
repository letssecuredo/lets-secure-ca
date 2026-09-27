"use strict";

const crypto = require("crypto");

const { getDb, COLLECTIONS } = require("../firebase/firestore");
const {
  buildCertificateDocument,
  buildRevocationDocument,
  CertStatus,
} = require("../models/schemas");
const {
  issueCertificate,
  verifyCertificateSignature,
  pemToCert,
  encryptSecret,
  decryptSecret,
} = require("../utils/crypto");
const { loadCAPrivateKeyPem, loadCACertPem } = require("./caService");
const { nowIso, addDays, CERT_ID_RE } = require("../utils/helpers");
const { logger } = require("../utils/logger");

const VALIDITY_DAYS = 365;
const KEY_BITS = 2048;

function newCertId() {
  return "LS-" + crypto.randomBytes(4).toString("hex").toUpperCase();
}

async function generateUniqueCertId() {
  const db = getDb();
  for (let i = 0; i < 8; i++) {
    const id = newCertId();
    const snap = await db.collection(COLLECTIONS.certificates).doc(id).get();
    if (!snap.exists) return id;
  }
  throw new Error("Could not generate a unique certificate ID");
}

function requireMasterKey() {
  const key = process.env.MASTER_ENCRYPTION_KEY;
  if (!key || key.length !== 64) {
    const err = new Error(
      "MASTER_ENCRYPTION_KEY is not configured (must be 64 hex chars)"
    );
    err.status = 500;
    throw err;
  }
  return key;
}

/* ==========================================================
   ISSUE
   ========================================================== */

/**
 * Issues a leaf certificate, encrypts its private key with the master key,
 * and persists both the public and encrypted-private material to Firestore.
 *
 * Returns { record, privateKeyPem } — privateKeyPem is a ONE-TIME value
 * returned to the caller for immediate download. It is never stored in
 * plaintext and never returned in subsequent API calls.
 */
async function issueNewCertificate({ owner, project, domain, email }) {
  const caPrivPem = await loadCAPrivateKeyPem();
  const caCertPem = await loadCACertPem();

  const issued = await issueCertificate({
    caPrivateKeyPem: caPrivPem,
    caCertPem,
    subject: { owner, project, domain, email },
    days: VALIDITY_DAYS,
    keyBits: KEY_BITS,
  });

  const certId = await generateUniqueCertId();
  const issuedAt = nowIso();
  const expiresAt = addDays(new Date(), VALIDITY_DAYS).toISOString();

  // Encrypt leaf private key with master key (same pattern as Root CA)
  const masterKey = requireMasterKey();
  const encryptedPrivateKey = encryptSecret(issued.privateKeyPem, masterKey);

  // Public JSON payload — deliberately excludes any private key material
  const jsonPayload = {
    certId,
    serialNumber: issued.serialNumber,
    owner,
    project,
    domain,
    email,
    issuer: "Let-S Secure CA",
    issuedAt,
    expiresAt,
    status: CertStatus.ACTIVE,
    fingerprint: issued.fingerprint,
    algorithm: "sha256WithRSA",
    keySize: KEY_BITS,
  };

  const record = buildCertificateDocument({
    certId,
    serialNumber: issued.serialNumber,
    owner,
    project,
    domain,
    email,
    issuedAt,
    expiresAt,
    publicKey: issued.publicKeyPem,
    signature: issued.signature,
    fingerprint: issued.fingerprint,
    leafCertPem: issued.certPem,
    caCertPem,
    encryptedPrivateKey, // ← persisted, AES-256-GCM encrypted
    jsonPayload,
  });

  // Single write — everything lives in one Firestore document
  await getDb().collection(COLLECTIONS.certificates).doc(certId).set(record);

  logger.info("Certificate issued", {
    certId,
    domain,
    serial: record.serialNumber,
    hasEncryptedKey: !!encryptedPrivateKey,
  });

  // Return the record + the plaintext PEM for one-time download
  return { record, privateKeyPem: issued.privateKeyPem };
}

/* ==========================================================
   READ
   ========================================================== */

async function getCertificate(certId) {
  if (!certId || !CERT_ID_RE.test(certId)) return null;
  const snap = await getDb().collection(COLLECTIONS.certificates).doc(certId).get();
  if (!snap.exists) return null;
  return { id: snap.id, ...snap.data() };
}

async function getCertificateByDomain(domain) {
  const snap = await getDb()
    .collection(COLLECTIONS.certificates)
    .where("domain", "==", domain)
    .limit(1)
    .get();
  if (snap.empty) return null;
  const doc = snap.docs[0];
  return { id: doc.id, ...doc.data() };
}

async function listCertificates({ limit = 100, offset = 0 } = {}) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const safeOffset = Math.max(Number(offset) || 0, 0);

  const snap = await getDb()
    .collection(COLLECTIONS.certificates)
    .orderBy("issuedAt", "desc")
    .limit(safeLimit + safeOffset)
    .get();

  const all = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  return all.slice(safeOffset, safeOffset + safeLimit);
}

async function getPem(certId) {
  const cert = await getCertificate(certId);
  if (!cert || !cert.leafCertPem) {
    const err = new Error("Certificate PEM not found");
    err.status = 404;
    throw err;
  }
  return cert.leafCertPem;
}

/**
 * Returns the decrypted leaf private key PEM.
 * Must be called only from an admin-authenticated endpoint.
 */
async function getPrivateKeyPem(certId) {
  const cert = await getCertificate(certId);
  if (!cert) {
    const err = new Error("Certificate not found");
    err.status = 404;
    throw err;
  }
  if (!cert.encryptedPrivateKey) {
    const err = new Error(
      "Private key not available for this certificate. " +
        "It may have been issued before encryption-at-rest was enabled."
    );
    err.status = 410;
    throw err;
  }

  const masterKey = requireMasterKey();
  try {
    return decryptSecret(cert.encryptedPrivateKey, masterKey);
  } catch (e) {
    logger.error("Private key decryption failed", {
      certId,
      error: e.message,
    });
    const err = new Error(
      "Private key could not be decrypted. MASTER_ENCRYPTION_KEY may have changed."
    );
    err.status = 500;
    throw err;
  }
}

/**
 * Returns the certificate metadata as a JSON-safe object.
 * Never includes private key material.
 */
async function getJsonPayload(certId) {
  const cert = await getCertificate(certId);
  if (!cert) {
    const err = new Error("Certificate not found");
    err.status = 404;
    throw err;
  }

  if (cert.jsonPayload) return cert.jsonPayload;

  return {
    certId: cert.certId,
    serialNumber: cert.serialNumber,
    owner: cert.owner,
    project: cert.project,
    domain: cert.domain,
    email: cert.email,
    issuer: cert.issuer,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    status: cert.status,
    fingerprint: cert.fingerprint,
    algorithm: cert.algorithm,
    keySize: cert.keySize,
  };
}

/**
 * Returns a combined fullchain PEM: leaf + CA (for Nginx/Apache).
 */
async function getFullchainPem(certId) {
  const cert = await getCertificate(certId);
  if (!cert || !cert.leafCertPem) {
    const err = new Error("Certificate PEM not found");
    err.status = 404;
    throw err;
  }
  const ca = cert.caCertPem || (await loadCACertPem());
  return cert.leafCertPem.trim() + "\n" + ca.trim() + "\n";
}

/* ==========================================================
   REVOKE
   ========================================================== */

async function revokeCertificate(certId, reason) {
  const cert = await getCertificate(certId);
  if (!cert) {
    const err = new Error("Certificate not found");
    err.status = 404;
    throw err;
  }
  if (cert.status === CertStatus.REVOKED) {
    return cert;
  }

  const revokedAt = nowIso();
  const safeReason = String(reason || "unspecified").slice(0, 200);

  await getDb().collection(COLLECTIONS.certificates).doc(certId).update({
    status: CertStatus.REVOKED,
    revokedAt,
    revocationReason: safeReason,
    "jsonPayload.status": CertStatus.REVOKED,
  });

  await getDb()
    .collection(COLLECTIONS.revocations)
    .doc(certId)
    .set(
      buildRevocationDocument({
        certId,
        serialNumber: cert.serialNumber,
        domain: cert.domain,
        reason: safeReason,
      })
    );

  logger.info("Certificate revoked", { certId, reason: safeReason });

  return {
    ...cert,
    status: CertStatus.REVOKED,
    revokedAt,
    revocationReason: safeReason,
  };
}

/* ==========================================================
   DELETE
   ========================================================== */

async function deleteCertificate(certId) {
  const cert = await getCertificate(certId);
  if (!cert) {
    const err = new Error("Certificate not found");
    err.status = 404;
    throw err;
  }

  await getDb().collection(COLLECTIONS.certificates).doc(certId).delete();
  // Revocation record (if any) is intentionally retained for audit purposes.

  logger.info("Certificate deleted", { certId });
  return true;
}

/* ==========================================================
   VERIFY
   ========================================================== */

async function verifyCertificateObject({ certId, certPem }) {
  const caCertPem = await loadCACertPem();

  let record = null;
  let pem = certPem;

  if (certId) {
    record = await getCertificate(certId);
    if (!record) return { valid: false, reason: "Certificate not found" };
    if (!pem) pem = record.leafCertPem;
  }

  if (!pem) return { valid: false, reason: "No certificate provided" };

  // 1. Parse
  let leaf;
  try {
    leaf = pemToCert(pem);
  } catch {
    return { valid: false, reason: "Malformed certificate PEM" };
  }

  // 2. Signature
  let sigOk = false;
  try {
    sigOk = verifyCertificateSignature(pem, caCertPem);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { valid: false, reason: "Signature verification failed" };

  // 3. Issuer
  const ca = pemToCert(caCertPem);
  const leafCN = leaf.issuer.getField("CN");
  const caCN = ca.subject.getField("CN");
  if (!leafCN || !caCN || leafCN.value !== caCN.value) {
    return { valid: false, reason: "Issuer mismatch" };
  }

  // 4. Expiration window
  const now = Date.now();
  if (new Date(leaf.validity.notBefore).getTime() > now) {
    return { valid: false, reason: "Certificate not yet valid" };
  }
  if (new Date(leaf.validity.notAfter).getTime() < now) {
    return { valid: false, reason: "Certificate expired" };
  }

  // 5. Revocation
  if (record) {
    if (record.status === CertStatus.REVOKED) {
      return { valid: false, reason: "Certificate revoked" };
    }
  } else {
    const serial = String(leaf.serialNumber || "").toUpperCase();
    if (serial) {
      const snap = await getDb()
        .collection(COLLECTIONS.certificates)
        .where("serialNumber", "==", serial)
        .limit(1)
        .get();
      if (!snap.empty && snap.docs[0].data().status === CertStatus.REVOKED) {
        return { valid: false, reason: "Certificate revoked" };
      }
    }
  }

  return { valid: true, reason: "" };
}

module.exports = {
  issueNewCertificate,
  getCertificate,
  getCertificateByDomain,
  listCertificates,
  getPem,
  getPrivateKeyPem,
  getFullchainPem,
  getJsonPayload,
  revokeCertificate,
  deleteCertificate,
  verifyCertificateObject,
};
