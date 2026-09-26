"use strict";

const {
  issueNewCertificate,
  getCertificate,
  getPem,
  getJsonPayload,
  verifyCertificateObject,
} = require("../services/certService");
const {
  createChallenge,
  getChallengeById,
  verifyChallenge,
  markChallengeUsed,
} = require("../services/challengeService");
const { isDomainPreVerified } = require("../services/verifiedDomainService");
const { getRootCA } = require("../services/caService");
const { logAction } = require("../services/auditService");
const { AuditAction } = require("../models/schemas");

/* ==========================================================
   REQUEST CERT (with auto pre-verified check)
   ========================================================== */

async function requestCert(req, res, next) {
  try {
    const { owner, project, domain, email } = req.validated;
    const method = String(req.body.method || "dns-01").toLowerCase();

    /* ---------- Step 1: Is the domain pre-verified by admin? ---------- */
    const preVerified = await isDomainPreVerified(domain);
    if (preVerified) {
      const cert = await issueNewCertificate({ owner, project, domain, email });

      await logAction({
        action: AuditAction.CERT_CREATED,
        actor: "public",
        target: cert.certId,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        success: true,
        meta: { domain, email, preVerified: preVerified.pattern },
      });

      return res.status(201).json({
        valid: true,
        status: "issued",
        preVerified: true,
        preVerifiedPattern: preVerified.pattern,
        certificate: cert.jsonPayload,
        downloadUrl: `/api/cert/${cert.certId}`,
        jsonUrl: `/api/cert/${cert.certId}/json`,
      });
    }

    /* ---------- Step 2: Standard challenge flow ---------- */
    const challenge = await createChallenge({
      owner,
      project,
      domain,
      email,
      method,
    });

    await logAction({
      action: AuditAction.CHALLENGE_CREATED,
      actor: "public",
      target: challenge.id,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
      meta: { domain, method },
    });

    const response = {
      valid: true,
      status: "challenge_pending",
      message: challenge.instructions,
      challenge: {
        id: challenge.id,
        domain: challenge.domain,
        method: challenge.method,
        token: challenge.token,
        status: challenge.status,
        attempts: 0,
        lastError: null,
        expiresAt: challenge.expiresAt,
        verifyUrl: `/api/verify-challenge/${challenge.id}`,
        statusUrl: `/api/challenge/${challenge.id}`,
      },
    };

    if (method === "dns-01") {
      response.challenge.dns = {
        type: "TXT",
        name: challenge.recordName,
        value: challenge.recordValue,
        ttl: 300,
      };
    } else if (method === "http-01") {
      response.challenge.http = {
        url: challenge.fileUrl,
        path: challenge.filePath,
        content: challenge.fileContent,
      };
    } else if (method === "tls-alpn-01") {
      response.challenge.tlsAlpn = {
        certPemUrl: `/api/challenge/${challenge.id}/provision-cert`,
        keyPemUrl: `/api/challenge/${challenge.id}/provision-key`,
        alpnProtocol: "acme-tls/1",
        port: 443,
      };
    }

    res.status(202).json(response);
  } catch (err) {
    next(err);
  }
}

/* ==========================================================
   CHALLENGE STATUS
   ========================================================== */

async function getChallengeStatus(req, res, next) {
  try {
    const challenge = await getChallengeById(req.params.id);
    if (!challenge) {
      return res.status(404).json({ valid: false, error: "Challenge not found" });
    }

    res.json({
      valid: true,
      challenge: {
        id: challenge.id,
        domain: challenge.domain,
        method: challenge.method,
        status: challenge.status,
        attempts: challenge.attempts || 0,
        lastError: challenge.lastError || null,
        createdAt: challenge.createdAt,
        expiresAt: challenge.expiresAt,
        verifiedAt: challenge.verifiedAt || null,
      },
    });
  } catch (err) {
    next(err);
  }
}

/* ==========================================================
   VERIFY CHALLENGE → ISSUE CERT
   ========================================================== */

async function verifyChallengeAndIssue(req, res, next) {
  try {
    const challenge = await verifyChallenge(req.params.id);

    const cert = await issueNewCertificate({
      owner: challenge.owner,
      project: challenge.project,
      domain: challenge.domain,
      email: challenge.email,
    });

    await markChallengeUsed(challenge.id);

    await logAction({
      action: AuditAction.CHALLENGE_VERIFIED,
      actor: "public",
      target: challenge.id,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
      meta: { certId: cert.certId, method: challenge.method },
    });

    res.status(201).json({
      valid: true,
      status: "issued",
      certificate: cert.jsonPayload,
      downloadUrl: `/api/cert/${cert.certId}`,
      jsonUrl: `/api/cert/${cert.certId}/json`,
    });
  } catch (err) {
    // Fire-and-forget audit log of failure
    try {
      await logAction({
        action: AuditAction.CHALLENGE_FAILED,
        actor: "public",
        target: req.params.id,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        success: false,
        meta: { reason: err.message },
      });
    } catch {}
    next(err);
  }
}

/* ==========================================================
   TLS-ALPN PROVISIONING FILES
   ========================================================== */

async function downloadProvisioningCert(req, res, next) {
  try {
    const challenge = await getChallengeById(req.params.id);
    if (!challenge || challenge.method !== "tls-alpn-01") {
      return res.status(404).json({ valid: false, error: "Not a TLS-ALPN-01 challenge" });
    }
    if (!challenge.provisionCertPem) {
      return res.status(404).json({ valid: false, error: "Provisioning cert not available" });
    }

    await logAction({
      action: AuditAction.PROVISION_CERT_DOWNLOADED,
      actor: "public",
      target: challenge.id,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      success: true,
    });

    res.setHeader("Content-Type", "application/x-pem-file");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${challenge.domain}-provision.crt.pem"`
    );
    res.send(challenge.provisionCertPem);
  } catch (err) {
    next(err);
  }
}

async function downloadProvisioningKey(req, res, next) {
  try {
    const challenge = await getChallengeById(req.params.id);
    if (!challenge || challenge.method !== "tls-alpn-01") {
      return res.status(404).json({ valid: false, error: "Not a TLS-ALPN-01 challenge" });
    }
    if (!challenge.provisionKeyPem) {
      return res.status(404).json({ valid: false, error: "Provisioning key not available" });
    }

    res.setHeader("Content-Type", "application/x-pem-file");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${challenge.domain}-provision.key.pem"`
    );
    res.send(challenge.provisionKeyPem);
  } catch (err) {
    next(err);
  }
}

/* ==========================================================
   VERIFY EXISTING CERTIFICATE
   ========================================================== */

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

/* ==========================================================
   STATUS / DOWNLOAD / ROOT CA
   ========================================================== */

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
  getChallengeStatus,
  verifyChallengeAndIssue,
  downloadProvisioningCert,
  downloadProvisioningKey,
  verifyCert,
  statusCert,
  downloadCert,
  downloadCertJson,
  rootCertPublic,
  publicCertLookup,
};
