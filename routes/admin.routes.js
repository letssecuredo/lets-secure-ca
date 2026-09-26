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
  auditLogs,
} = require("../controllers/admin.controller");

/* Public */
router.post("/login", authLimiter, validateLogin, adminLogin);

/* Admin-only */
router.post("/create-root-ca", authMiddleware, adminMiddleware, createRootCA);
router.get("/root-ca", authMiddleware, adminMiddleware, getRootCAInfo);
router.get("/certificates", authMiddleware, adminMiddleware, listAllCertificates);
router.post("/revoke-cert", authMiddleware, adminMiddleware, revokeCert);
router.delete("/certificate/:id", authMiddleware, adminMiddleware, validateCertIdParam, deleteCert);
router.get("/audit-logs", authMiddleware, adminMiddleware, auditLogs);

module.exports = router;
