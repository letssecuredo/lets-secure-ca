"use strict";

const {
  issueNewCertificate,
  getCertificate,
  getPem,
  getJsonPayload,
  verifyCertificateObject,
} = require("../services/certService");
const { getRootCA } = require("../services/caService");
const { logAction } = require("../services/auditService");
const { AuditAction } = require("../models/schemas");

async function requestCert(req, res, next) {
  try {
    const { owner, project, domain, email } = req.validated;
    const cert = await issueNewCertificate({ owner, project, domain, email });

    await logAction({
      action: AuditAction.CERT_CREATED,
      actor: "public",
      target: cert.certId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
      meta: { domain, email },
    });

    res.status(201).json({
      valid: true,
      certificate: cert.jsonPayload,
      downloadUrl: `/api/cert/${cert.certId}`,
      jsonUrl: `/api/cert/${cert.certId}/json`,
    });
  } catch (err) {
    next(err);
  }
}

async function verifyCert(req, res, next) {
  try {
    const { certId, certPem } = req.validated;
    const result = await verifyCertificateObject({ certId, certPem });

    await logAction({
      action: AuditAction.CERT_VERIFIED,
      actor: "public",
      target: certId || "inline-pem",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: result.valid,
      meta: result.valid ? null : { reason: result.reason },
    });

    res.json(result);
  } catch (err) {
    next(err);
  }
}

async function statusCert(req, res, next) {
  try {
    const cert = await getCertificate(req.certId);
    if (!cert) {
      return res.status(404).json({ valid: false, error: "Certificate not found" });
    }
    res.json({
      valid: true,
      certificate: {
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
        revokedAt: cert.revokedAt || null,
        revocationReason: cert.revocationReason || null,
        fingerprint: cert.fingerprint,
      },
    });
  } catch (err) {
    next(err);
  }
}

async function downloadCert(req, res, next) {
  try {
    const certId = req.certId;
    const cert = await getCertificate(certId);
    if (!cert) {
      return res.status(404).json({ valid: false, error: "Certificate not found" });
    }

    const pem = await getPem(certId);

    await logAction({
      action: AuditAction.CERT_DOWNLOADED,
      actor: "public",
      target: certId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
    });

    res.setHeader("Content-Type", "application/x-pem-file");
    res.setHeader("Content-Disposition", `attachment; filename="${certId}.pem"`);
    res.setHeader("Cache-Control", "private, no-store");
    res.send(pem);
  } catch (err) {
    next(err);
  }
}

async function downloadCertJson(req, res, next) {
  try {
    const certId = req.certId;
    const json = await getJsonPayload(certId);

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="${certId}.json"`);
    res.setHeader("Cache-Control", "private, no-store");
    res.send(JSON.stringify(json, null, 2));
  } catch (err) {
    next(err);
  }
}

async function rootCertPublic(req, res, next) {
  try {
    const root = await getRootCA();
    if (!root) {
      return res.status(404).json({ valid: false, error: "Root CA not initialized" });
    }
    res.setHeader("Content-Type", "application/x-pem-file");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="lets-secure-root-ca.pem"'
    );
    res.send(root.certPem);
  } catch (err) {
    next(err);
  }
}

async function publicCertLookup(req, res, next) {
  try {
    const cert = await getCertificate(req.certId);
    if (!cert) {
      return res.status(404).json({ valid: false, error: "Certificate not found" });
    }
    res.json({
      valid: true,
      certificate: {
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
        revokedAt: cert.revokedAt || null,
        revocationReason: cert.revocationReason || null,
        fingerprint: cert.fingerprint,
        algorithm: cert.algorithm,
        keySize: cert.keySize,
      },
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  requestCert,
  verifyCert,
  statusCert,
  downloadCert,
  downloadCertJson,
  rootCertPublic,
  publicCertLookup,
};
