"use strict";

/**
 * Canonical Firestore document shapes.
 * PEM content is stored inline (base64 is unnecessary — PEM is already ASCII).
 */

const CertStatus = Object.freeze({
  ACTIVE: "active",
  REVOKED: "revoked",
  EXPIRED: "expired",
});

const AuditAction = Object.freeze({
  ADMIN_LOGIN: "ADMIN_LOGIN",
  ADMIN_LOGIN_FAILED: "ADMIN_LOGIN_FAILED",
  ROOT_CA_CREATED: "ROOT_CA_CREATED",
  CERT_CREATED: "CERT_CREATED",
  CERT_VERIFIED: "CERT_VERIFIED",
  CERT_DOWNLOADED: "CERT_DOWNLOADED",
  CERT_REVOKED: "CERT_REVOKED",
  CERT_DELETED: "CERT_DELETED",
});

/**
 * certificates/{certId}
 * — Full PEM is stored inline. No Storage dependency.
 */
function buildCertificateDocument(input) {
  return {
    certId: input.certId,
    serialNumber: input.serialNumber,
    owner: input.owner,
    project: input.project,
    domain: input.domain,
    email: input.email,
    issuer: "Let-S Secure CA",
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    publicKey: input.publicKey,
    signature: input.signature,
    fingerprint: input.fingerprint,
    status: CertStatus.ACTIVE,
    revokedAt: null,
    revocationReason: null,
    algorithm: "sha256WithRSA",
    keySize: 2048,

    // Inline certificate material
    leafCertPem: input.leafCertPem,
    caCertPem: input.caCertPem,

    // Inline public JSON blob (same shape as the API response)
    jsonPayload: input.jsonPayload,
  };
}

/**
 * users/{uid}
 */
function buildUserDocument({ email, passwordHash, role = "admin" }) {
  return {
    email,
    passwordHash,
    role,
    disabled: false,
    createdAt: new Date().toISOString(),
  };
}

/**
 * revocations/{certId}
 */
function buildRevocationDocument({ certId, serialNumber, domain, reason }) {
  return {
    certId,
    serialNumber,
    domain,
    reason: reason || "unspecified",
    revokedAt: new Date().toISOString(),
  };
}

/**
 * audit_logs/{auto}
 */
function buildAuditLog({ action, actor, target, meta, ip, userAgent, success }) {
  return {
    action,
    actor: actor || "system",
    target: target || null,
    meta: meta || null,
    ip: ip || null,
    userAgent: userAgent || null,
    success: !!success,
    timestamp: new Date().toISOString(),
  };
}

/**
 * system/root-ca
 */
function buildRootCADocument({
  subject,
  certPem,
  serialNumber,
  fingerprint,
  algorithm,
  validityDays,
  encryptedPrivateKey,
}) {
  return {
    subject,
    certPem,
    serialNumber,
    fingerprint,
    algorithm,
    validityDays,
    encryptedPrivateKey,
    createdAt: new Date().toISOString(),
  };
}

module.exports = {
  CertStatus,
  AuditAction,
  buildCertificateDocument,
  buildUserDocument,
  buildRevocationDocument,
  buildAuditLog,
  buildRootCADocument,
};
