"use strict";

const express = require("express");
const router = express.Router();

const adminRoutes = require("./admin.routes");
const certRoutes = require("./cert.routes");

/* ==========================================================
   HEALTH / ROOT
   ========================================================== */

router.get("/", (req, res) => {
  res.json({
    name: "Let-S Secure Private CA",
    status: "ok",
    version: "1.1.0",
    time: new Date().toISOString(),
    requestId: req.id,
    endpoints: {
      requestCert: "POST /api/request-cert (challenge flow)",
      challengeStatus: "GET /api/challenge/:id",
      verifyChallenge: "POST /api/verify-challenge/:id",
      provisionCert: "GET /api/challenge/:id/provision-cert (TLS-ALPN-01)",
      provisionKey: "GET /api/challenge/:id/provision-key (TLS-ALPN-01)",
      verifyCert: "POST /api/verify-cert",
      status: "GET /api/status/:id",
      download: "GET /api/cert/:id",
      rootCert: "GET /api/root-ca.pem",
      adminLogin: "POST /api/admin/login",
      adminCreateRootCA: "POST /api/admin/create-root-ca",
      adminRootCAInfo: "GET /api/admin/root-ca",
      adminListCerts: "GET /api/admin/certificates",
      adminRevoke: "POST /api/admin/revoke-cert",
      adminDelete: "DELETE /api/admin/certificate/:id",
      adminVerifiedDomains: "GET|POST /api/admin/verified-domains",
      adminVerifiedDomainDelete: "DELETE /api/admin/verified-domains/:id",
      adminAuditLogs: "GET /api/admin/audit-logs",
    },
    verificationMethods: ["dns-01", "http-01", "tls-alpn-01", "pre-verified"],
  });
});

router.get("/healthz", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/* ==========================================================
   ROUTES
   ========================================================== */

router.use("/api/admin", adminRoutes);
router.use("/api", certRoutes);

module.exports = router;
