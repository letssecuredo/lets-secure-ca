"use strict";

const { getDb, COLLECTIONS } = require("../firebase/firestore");
const { buildRootCADocument } = require("../models/schemas");
const {
  createRootCA,
  encryptSecret,
  decryptSecret,
} = require("../utils/crypto");
const { logger } = require("../utils/logger");

const ROOT_DOC = "root-ca";
const SYSTEM_COLLECTION = COLLECTIONS.system;

async function getRootCA() {
  const snap = await getDb().collection(SYSTEM_COLLECTION).doc(ROOT_DOC).get();
  if (!snap.exists) return null;
  return snap.data();
}

async function rootCAExists() {
  return !!(await getRootCA());
}

function requireMasterKey() {
  const key = process.env.MASTER_ENCRYPTION_KEY;
  if (!key || key.length !== 64) {
    const err = new Error("MASTER_ENCRYPTION_KEY is not configured (must be 64 hex chars)");
    err.status = 500;
    throw err;
  }
  return key;
}

async function createRoot({ subject, days = 3650, bits = 4096 }) {
  if (await rootCAExists()) {
    const err = new Error("Root CA already exists");
    err.status = 409;
    throw err;
  }

  const masterKey = requireMasterKey();

  logger.info("Generating Root CA keypair", { bits, days });
  const ca = await createRootCA({ subject, days, bits });

  const encrypted = encryptSecret(ca.privateKeyPem, masterKey);

  const record = buildRootCADocument({
    subject,
    certPem: ca.certPem,
    serialNumber: ca.serialNumber,
    fingerprint: ca.fingerprint,
    algorithm: `RSA-${bits} / SHA-256`,
    validityDays: days,
    encryptedPrivateKey: encrypted,
  });

  // Single Firestore document holds everything the CA needs.
  await getDb().collection(SYSTEM_COLLECTION).doc(ROOT_DOC).set(record);

  logger.info("Root CA created", {
    serial: ca.serialNumber,
    fingerprint: ca.fingerprint,
  });

  return {
    subject,
    certPem: ca.certPem,
    serialNumber: ca.serialNumber,
    fingerprint: ca.fingerprint,
  };
}

async function loadCAPrivateKeyPem() {
  const root = await getRootCA();
  if (!root) {
    const err = new Error(
      "Root CA not initialized. An admin must call POST /api/admin/create-root-ca"
    );
    err.status = 503;
    throw err;
  }
  const masterKey = requireMasterKey();
  return decryptSecret(root.encryptedPrivateKey, masterKey);
}

async function loadCACertPem() {
  const root = await getRootCA();
  if (!root) {
    const err = new Error("Root CA not initialized");
    err.status = 503;
    throw err;
  }
  return root.certPem;
}

module.exports = {
  getRootCA,
  rootCAExists,
  createRoot,
  loadCAPrivateKeyPem,
  loadCACertPem,
};
