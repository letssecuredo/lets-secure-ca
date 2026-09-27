"use strict";

const express = require("express");
const router = express.Router();

const { issueLimiter } = require("../middleware/rateLimitMiddleware");
const { authMiddleware } = require("../middleware/authMiddleware");
const { adminMiddleware } = require("../middleware/adminMiddleware");
const {
  validateRequestCert,
  validateVerifyCert,
  validateCertIdParam,
  validateChallengeIdParam,
  validateDomainParam,
} = require("../middleware/validationMiddleware");

const {
  requestCert,
  getChallengeStatus,
  verifyChallengeAndIssue,
  downloadProvisioningCert,
  downloadProvisioningKey,
  verifyCert,
  statusCert,
  downloadCert,
  downloadFullchain,
  downloadPrivateKey,
  downloadCertJson,
  rootCertPublic,
  publicCertLookup,
} = require("../controllers/cert.controller");
const { getCertificateByDomain } = require("../services/certService");

/* ==========================================================
   DOMAIN VERIFICATION FLOW
   ========================================================== */

router.post("/request-cert", issueLimiter, validateRequestCert, requestCert);
router.get("/challenge/:id", validateChallengeIdParam, getChallengeStatus);
router.post("/verify-challenge/:id", validateChallengeIdParam, verifyChallengeAndIssue);

// TLS-ALPN-01 provisioning files
router.get("/challenge/:id/provision-cert", validateChallengeIdParam, downloadProvisioningCert);
router.get("/challenge/:id/provision-key", validateChallengeIdParam, downloadProvisioningKey);

/* ==========================================================
   CERTIFICATE OPERATIONS (public material)
   ========================================================== */

router.post("/verify-cert", validateVerifyCert, verifyCert);
router.get("/status/:id", validateCertIdParam, statusCert);
router.get("/cert/:id", validateCertIdParam, downloadCert);
router.get("/cert/:id/fullchain", validateCertIdParam, downloadFullchain);
router.get("/cert/:id/json", validateCertIdParam, downloadCertJson);
router.get("/root-ca.pem", rootCertPublic);

/* ==========================================================
   PRIVATE KEY DOWNLOAD (admin-only)
   ==========================================================
   The private key is encrypted at rest. This endpoint decrypts it
   in-memory and streams it. It requires BOTH:
     - a valid admin JWT (authMiddleware)
     - admin role         (adminMiddleware)
   Every call is audit-logged.
   ========================================================== */

router.get(
  "/cert/:id/key",
  validateCertIdParam,
  authMiddleware,
  adminMiddleware,
  downloadPrivateKey
);

/* ==========================================================
   FRONTEND-COMPATIBLE ALIASES
   ========================================================== */

router.post("/certificates", issueLimiter, validateRequestCert, requestCert);
router.get("/certificates/:id", validateCertIdParam, publicCertLookup);
router.get(
  "/certificates/domain/:domain",
  validateDomainParam,
  async (req, res, next) => {
    try {
      const cert = await getCertificateByDomain(req.domain);
      if (!cert) return res.status(404).json({ valid: false, error: "Certificate not found" });
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
);
router.get("/certificates/:id/pem", validateCertIdParam, downloadCert);

module.exports = router;
