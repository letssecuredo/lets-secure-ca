"use strict";

const express = require("express");
const router = express.Router();

const { issueLimiter } = require("../middleware/rateLimitMiddleware");
const {
  validateRequestCert,
  validateVerifyCert,
  validateCertIdParam,
  validateDomainParam,
} = require("../middleware/validationMiddleware");

const {
  requestCert,
  getChallengeStatus,
  verifyChallengeAndIssue,
  verifyCert,
  statusCert,
  downloadCert,
  downloadCertJson,
  rootCertPublic,
  publicCertLookup,
} = require("../controllers/cert.controller");
const { getCertificateByDomain } = require("../services/certService");

/* ==========================================================
   DOMAIN VERIFICATION FLOW (new)
   ========================================================== */

// Step 1: Request a certificate → returns a challenge (DNS TXT or HTTP file)
router.post("/request-cert", issueLimiter, validateRequestCert, requestCert);

// Step 2: Get challenge status (poll for the frontend)
router.get("/challenge/:id", getChallengeStatus);

// Step 3: Verify the challenge → issues the certificate if the challenge passes
router.post("/verify-challenge/:id", verifyChallengeAndIssue);

/* ==========================================================
   CERTIFICATE OPERATIONS
   ========================================================== */

router.post("/verify-cert", validateVerifyCert, verifyCert);
router.get("/status/:id", validateCertIdParam, statusCert);
router.get("/cert/:id", validateCertIdParam, downloadCert);
router.get("/cert/:id/json", validateCertIdParam, downloadCertJson);
router.get("/root-ca.pem", rootCertPublic);

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
