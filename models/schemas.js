"use strict";

const CertStatus = Object.freeze({
  ACTIVE: "active",
  REVOKED: "revoked",
  EXPIRED: "expired",
});

const ChallengeStatus = Object.freeze({
  PENDING: "pending",
  VERIFIED: "verified",
  USED: "used",
  EXPIRED: "expired",
});

const ChallengeMethod = Object.freeze({
  DNS_01: "dns-01",
  HTTP_01: "http-01",
  TLS_ALPN_01: "tls-alpn-01",
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
  CHALLENGE_CREATED: "CHALLENGE_CREATED",
  CHALLENGE_VERIFIED: "CHALLENGE_VERIFIED",
  CHALLENGE_FAILED: "CHALLENGE_FAILED",
  PROVISION_CERT_DOWNLOADED: "PROVISION_CERT_DOWNLOADED",
  VERIFIED_DOMAIN_ADDED: "VERIFIED_DOMAIN_ADDED",
  VERIFIED_DOMAIN_REMOVED: "VERIFIED_DOMAIN_REMOVED",
});

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
    leafCertPem: input.leafCertPem,
    caCertPem: input.caCertPem,
    jsonPayload: input.jsonPayload,
  };
}

function buildUserDocument({ email, passwordHash, role = "admin" }) {
  return {
    email,
    passwordHash,
    role,
    disabled: false,
    createdAt: new Date().toISOString(),
  };
}

function buildRevocationDocument({ certId, serialNumber, domain, reason }) {
  return {
    certId,
    serialNumber,
    domain,
    reason: reason || "unspecified",
    revokedAt: new Date().toISOString(),
  };
}

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

function buildVerifiedDomainDocument({ pattern, createdBy }) {
  return {
    pattern,
    createdBy,
    createdAt: new Date().toISOString(),
  };
}

module.exports = {
  CertStatus,
  ChallengeStatus,
  ChallengeMethod,
  AuditAction,
  buildCertificateDocument,
  buildUserDocument,
  buildRevocationDocument,
  buildAuditLog,
  buildRootCADocument,
  buildVerifiedDomainDocument,
};
