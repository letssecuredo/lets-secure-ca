"use strict";

const rateLimit = require("express-rate-limit");

const generalLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { valid: false, error: "Too many requests. Please try again later." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.AUTH_RATE_LIMIT_MAX) || 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { valid: false, error: "Too many login attempts. Please try again later." },
});

const issueLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.ISSUE_RATE_LIMIT_MAX) || 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { valid: false, error: "Certificate issuance rate limit reached." },
});

module.exports = { generalLimiter, authLimiter, issueLimiter };
