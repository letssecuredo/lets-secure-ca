"use strict";

const express = require("express");
const router = express.Router();

const { authMiddleware } = require("../middleware/authMiddleware");
const { adminMiddleware } = require("../middleware/adminMiddleware");
const { authLimiter } = require("../middleware/rateLimitMiddleware");
const {
  validateLogin,
  validateCertIdParam,
} = require("../middleware/validationMiddleware");

const {
  adminLogin,
  createRootCA,
  getRootCAInfo,
  listAllCertificates,
  revokeCert,
  deleteCert,
  listVerifiedDomainsHandler,
  addVerifiedDomainHandler,
  removeVerifiedDomainHandler,
  auditLogs,
} = require("../controllers/admin.controller");

/* ---------- Public ---------- */
router.post("/login", authLimiter, validateLogin, adminLogin);

/* ---------- Admin-only: Root CA ---------- */
router.post("/create-root-ca", authMiddleware, adminMiddleware, createRootCA);
router.get("/root-ca", authMiddleware, adminMiddleware, getRootCAInfo);

/* ---------- Admin-only: Certificates ---------- */
router.get("/certificates", authMiddleware, adminMiddleware, listAllCertificates);
router.post("/revoke-cert", authMiddleware, adminMiddleware, revokeCert);
router.delete(
  "/certificate/:id",
  authMiddleware,
  adminMiddleware,
  validateCertIdParam,
  deleteCert
);

/* ---------- Admin-only: Pre-verified domains ---------- */
router.get("/verified-domains", authMiddleware, adminMiddleware, listVerifiedDomainsHandler);
router.post("/verified-domains", authMiddleware, adminMiddleware, addVerifiedDomainHandler);
router.delete(
  "/verified-domains/:id",
  authMiddleware,
  adminMiddleware,
  removeVerifiedDomainHandler
);

/* ---------- Admin-only: Audit logs ---------- */
router.get("/audit-logs", authMiddleware, adminMiddleware, auditLogs);

module.exports = router;
