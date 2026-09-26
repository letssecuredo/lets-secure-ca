"use strict";

const {
  DOMAIN_RE,
  EMAIL_RE,
  CERT_ID_RE,
  sanitize,
} = require("../utils/helpers");

function validateRequestCert(req, res, next) {
  const body = req.body || {};

  const owner = sanitize(body.owner);
  const project = sanitize(body.project);
  const domain = sanitize(body.domain).toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const email = sanitize(body.email).toLowerCase();

  const errors = [];
  if (!owner || owner.length < 2 || owner.length > 120) errors.push("owner is required (2-120 chars)");
  if (!project || project.length < 2 || project.length > 120) errors.push("project is required (2-120 chars)");
  if (!domain || !DOMAIN_RE.test(domain)) errors.push("domain is invalid");
  if (!email || !EMAIL_RE.test(email)) errors.push("email is invalid");

  if (errors.length) {
    return res.status(400).json({ valid: false, error: errors.join("; ") });
  }

  req.validated = { owner, project, domain, email };
  next();
}

function validateVerifyCert(req, res, next) {
  const body = req.body || {};
  let pem = body.certPem || body.pem || body.certificate;
  const certId = sanitize(body.certId || body.id || "").toUpperCase();

  if (!pem && !certId) {
    return res.status(400).json({ valid: false, error: "Provide certId or certPem" });
  }
  if (certId && !CERT_ID_RE.test(certId)) {
    return res.status(400).json({ valid: false, error: "certId format invalid (expected LS-XXXXXXXX)" });
  }
  if (pem) {
    if (typeof pem !== "string") {
      return res.status(400).json({ valid: false, error: "certPem must be a string" });
    }
    pem = pem.trim();
    if (pem.length < 100 || pem.length > 20000) {
      return res.status(400).json({ valid: false, error: "certPem length out of range" });
    }
    if (!pem.includes("-----BEGIN CERTIFICATE-----") || !pem.includes("-----END CERTIFICATE-----")) {
      return res.status(400).json({ valid: false, error: "certPem is not a valid PEM block" });
    }
  }

  req.validated = { certId: certId || null, certPem: pem || null };
  next();
}

function validateCertIdParam(req, res, next) {
  const id = String(req.params.id || "").toUpperCase();
  if (!CERT_ID_RE.test(id)) {
    return res.status(400).json({ valid: false, error: "Invalid certificate ID format" });
  }
  req.certId = id;
  next();
}

function validateDomainParam(req, res, next) {
  const domain = String(req.params.domain || "").toLowerCase().trim();
  if (!DOMAIN_RE.test(domain)) {
    return res.status(400).json({ valid: false, error: "Invalid domain format" });
  }
  req.domain = domain;
  next();
}

function validateLogin(req, res, next) {
  const body = req.body || {};
  const email = sanitize(body.email).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";

  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ valid: false, error: "Invalid email" });
  }
  if (!password || password.length < 8 || password.length > 256) {
    return res.status(400).json({ valid: false, error: "Password must be 8-256 characters" });
  }

  req.validated = { email, password };
  next();
}

module.exports = {
  validateRequestCert,
  validateVerifyCert,
  validateCertIdParam,
  validateDomainParam,
  validateLogin,
};
