"use strict";

const admin = require("firebase-admin");
const { logger } = require("../utils/logger");

let db = null;

function initFirestore() {
  if (db) return db;

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
      }),
      // No storageBucket — we don't use Firebase Storage.
    });
  }

  db = admin.firestore();
  db.settings({ ignoreUndefinedProperties: true });

  logger.info("Firestore initialized", {
    projectId: process.env.FIREBASE_PROJECT_ID,
  });
  return db;
}

function getDb() {
  if (!db) initFirestore();
  return db;
}

const COLLECTIONS = Object.freeze({
  certificates: "certificates",
  users: "users",
  revocations: "revocations",
  audit_logs: "audit_logs",
  system: "system",
  challenges: "challenges",
});

module.exports = { initFirestore, getDb, COLLECTIONS };
