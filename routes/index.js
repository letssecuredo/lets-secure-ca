"use strict";

const express = require("express");
const router = express.Router();

const adminRoutes = require("./admin.routes");
const certRoutes = require("./cert.routes");

/**
 * Health / root
 */
router.get("/", (req, res) => {
  res.json({
    name: "Let-S Secure Private CA",
    status: "ok",
    version: "1.0.0",
    time: new Date().toISOString(),
    requestId: req.id,
    endpoints: {
      requestCert: "POST /api/request-cert",
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
      adminAuditLogs: "GET /api/admin/audit-logs",
    },
  });
});

router.get("/healthz", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

router.use("/api/admin", adminRoutes);
router.use("/api", certRoutes);

module.exports = router;
