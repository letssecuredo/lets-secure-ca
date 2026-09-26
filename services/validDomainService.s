"use strict";

const crypto = require("crypto");
const { getDb, COLLECTIONS } = require("../firebase/firestore");
const { buildVerifiedDomainDocument } = require("../models/schemas");
const { logger } = require("../utils/logger");

/**
 * Wildcard-aware domain matcher.
 *   "*"               → matches everything
 *   "*.example.com"   → matches "api.example.com", "www.example.com"
 *   "example.com"     → exact match
 */
function patternMatches(pattern, domain) {
  if (!pattern || !domain) return false;
  const p = pattern.toLowerCase().trim();
  const d = String(domain).toLowerCase().trim();

  if (p === "*") return true;

  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return d === base || d.endsWith("." + base);
  }

  return p === d;
}

/**
 * Returns the first matching pattern record, or null.
 */
async function isDomainPreVerified(domain) {
  const snap = await getDb().collection(COLLECTIONS.verifiedDomains).get();
  for (const doc of snap.docs) {
    const data = doc.data();
    if (patternMatches(data.pattern, domain)) {
      return { id: doc.id, ...data };
    }
  }
  return null;
}

async function addVerifiedDomain({ pattern, createdBy }) {
  const clean = String(pattern || "").trim().toLowerCase();
  if (!clean) {
    const err = new Error("pattern is required");
    err.status = 400;
    throw err;
  }

  const snap = await getDb()
    .collection(COLLECTIONS.verifiedDomains)
    .where("pattern", "==", clean)
    .limit(1)
    .get();

  if (!snap.empty) {
    const err = new Error("Pattern already exists");
    err.status = 409;
    throw err;
  }

  const id = "VD-" + crypto.randomBytes(4).toString("hex").toUpperCase();
  const record = {
    id,
    ...buildVerifiedDomainDocument({ pattern: clean, createdBy }),
  };

  await getDb().collection(COLLECTIONS.verifiedDomains).doc(id).set(record);
  logger.info("Verified domain added", { id, pattern: clean, by: createdBy });
  return record;
}

async function removeVerifiedDomain(id) {
  const snap = await getDb().collection(COLLECTIONS.verifiedDomains).doc(id).get();
  if (!snap.exists) {
    const err = new Error("Verified domain not found");
    err.status = 404;
    throw err;
  }
  await getDb().collection(COLLECTIONS.verifiedDomains).doc(id).delete();
  logger.info("Verified domain removed", { id });
  return true;
}

async function listVerifiedDomains() {
  const snap = await getDb()
    .collection(COLLECTIONS.verifiedDomains)
    .orderBy("createdAt", "desc")
    .get();
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

module.exports = {
  patternMatches,
  isDomainPreVerified,
  addVerifiedDomain,
  removeVerifiedDomain,
  listVerifiedDomains,
};
