"use strict";

const { login } = require("../services/authService");
const { createRoot, getRootCA } = require("../services/caService");
const {
  listCertificates,
  revokeCertificate,
  deleteCertificate,
} = require("../services/certService");
const { getLogs, logAction } = require("../services/auditService");
const { AuditAction } = require("../models/schemas");
const { CERT_ID_RE } = require("../utils/helpers");

async function adminLogin(req, res, next) {
  try {
    const { email, password } = req.validated;
    const result = await login({ email, password });

    if (!result || result.error) {
      await logAction({
        action: AuditAction.ADMIN_LOGIN_FAILED,
        actor: email,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        success: false,
        meta: result && result.error ? { reason: result.error } : { reason: "bad_credentials" },
      });
      return res.status(401).json({ valid: false, error: "Invalid credentials" });
    }

    await logAction({
      action: AuditAction.ADMIN_LOGIN,
      actor: result.user.email,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
    });

    res.json({ valid: true, token: result.token, user: result.user });
  } catch (err) {
    next(err);
  }
}

async function createRootCA(req, res, next) {
  try {
    const subject = {
      commonName: "Let-S Secure Root CA",
      organization: "Let-S Secure",
      ou: "Private Certificate Authority",
      country: "IN",
    };

    const created = await createRoot({ subject, days: 3650, bits: 4096 });

    await logAction({
      action: AuditAction.ROOT_CA_CREATED,
      actor: req.user.email,
      target: created.serialNumber,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
      meta: { fingerprint: created.fingerprint },
    });

    res.status(201).json({
      valid: true,
      rootCA: {
        subject: created.subject,
        serialNumber: created.serialNumber,
        fingerprint: created.fingerprint,
        certPem: created.certPem,
      },
    });
  } catch (err) {
    next(err);
  }
}

async function getRootCAInfo(req, res, next) {
  try {
    const root = await getRootCA();
    if (!root) {
      return res.status(404).json({ valid: false, error: "Root CA not initialized" });
    }
    res.json({
      valid: true,
      rootCA: {
        subject: root.subject,
        serialNumber: root.serialNumber,
        fingerprint: root.fingerprint,
        algorithm: root.algorithm,
        validityDays: root.validityDays,
        createdAt: root.createdAt,
        certPem: root.certPem,
      },
    });
  } catch (err) {
    next(err);
  }
}

async function listAllCertificates(req, res, next) {
  try {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const items = await listCertificates({ limit, offset });

    // Admin view omits PEM / public key blobs by default to keep the payload small.
    const certificates = items.map((c) => ({
      certId: c.certId,
      serialNumber: c.serialNumber,
      owner: c.owner,
      project: c.project,
      domain: c.domain,
      email: c.email,
      issuer: c.issuer,
      issuedAt: c.issuedAt,
      expiresAt: c.expiresAt,
      status: c.status,
      revokedAt: c.revokedAt || null,
      revocationReason: c.revocationReason || null,
      fingerprint: c.fingerprint,
    }));

    res.json({ valid: true, count: certificates.length, certificates });
  } catch (err) {
    next(err);
  }
}

async function revokeCert(req, res, next) {
  try {
    const certId = String(req.body.certId || req.body.id || "").toUpperCase();
    if (!CERT_ID_RE.test(certId)) {
      return res.status(400).json({ valid: false, error: "Invalid certId" });
    }

    const reason = String(req.body.reason || "unspecified").slice(0, 200);
    const cert = await revokeCertificate(certId, reason);

    await logAction({
      action: AuditAction.CERT_REVOKED,
      actor: req.user.email,
      target: certId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
      meta: { reason },
    });

    res.json({ valid: true, certificate: cert });
  } catch (err) {
    next(err);
  }
}

async function deleteCert(req, res, next) {
  try {
    const certId = req.certId;
    await deleteCertificate(certId);

    await logAction({
      action: AuditAction.CERT_DELETED,
      actor: req.user.email,
      target: certId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
    });

    res.json({ valid: true, message: "Certificate deleted" });
  } catch (err) {
    next(err);
  }
}

async function auditLogs(req, res, next) {
  try {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const action = req.query.action ? String(req.query.action) : null;

    const logs = await getLogs({ limit, offset, action });
    res.json({ valid: true, count: logs.length, logs });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  adminLogin,
  createRootCA,
  getRootCAInfo,
  listAllCertificates,
  revokeCert,
  deleteCert,
  auditLogs,
};
