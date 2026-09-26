"use strict";

function nowIso() {
  return new Date().toISOString();
}

function addDays(date, days) {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

const DOMAIN_RE =
  /^(?!-)(?:[a-zA-Z0-9\u00a1-\uffff](?:[a-zA-Z0-9\u00a1-\uffff-]{0,61}[a-zA-Z0-9\u00a1-\uffff])?\.)+[a-zA-Z\u00a1-\uffff]{2,}$/;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CERT_ID_RE = /^LS-[A-F0-9]{8}$/;

/**
 * Strip control chars and HTML angle brackets to prevent log/HTML injection.
 * Not a replacement for parameterized queries — Firestore is safe by design.
 */
function sanitize(input) {
  if (typeof input !== "string") return "";
  return input
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, 256);
}

function isProd() {
  return String(process.env.NODE_ENV || "").toLowerCase() === "production";
}

module.exports = {
  nowIso,
  addDays,
  DOMAIN_RE,
  EMAIL_RE,
  CERT_ID_RE,
  sanitize,
  isProd,
};
