"use strict";

const jwt = require("jsonwebtoken");
const { getDb, COLLECTIONS } = require("../firebase/firestore");
const { buildUserDocument } = require("../models/schemas");
const { hashPassword, verifyPassword } = require("../utils/crypto");
const { logger } = require("../utils/logger");

/**
 * Creates the first admin user if none exists.
 * Uses ADMIN_EMAIL / ADMIN_PASSWORD from .env.
 */
async function ensureAdminBootstrap() {
  const email = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
  const password = process.env.ADMIN_PASSWORD || "";

  if (!email || !password) {
    logger.warn("ADMIN_EMAIL / ADMIN_PASSWORD not set — bootstrap skipped");
    return;
  }
  if (password.length < 8) {
    logger.warn("ADMIN_PASSWORD too short (<8 chars) — bootstrap skipped");
    return;
  }

  const db = getDb();
  const snap = await db
    .collection(COLLECTIONS.users)
    .where("role", "==", "admin")
    .limit(1)
    .get();

  if (!snap.empty) {
    logger.info("Admin already exists — bootstrap skipped");
    return;
  }

  const doc = buildUserDocument({
    email,
    passwordHash: hashPassword(password),
    role: "admin",
  });

  await db.collection(COLLECTIONS.users).add(doc);
  logger.info("Admin user bootstrapped", { email });
}

async function login({ email, password }) {
  const db = getDb();

  const snap = await db
    .collection(COLLECTIONS.users)
    .where("email", "==", email)
    .limit(1)
    .get();

  if (snap.empty) return null;

  const doc = snap.docs[0];
  const user = doc.data();

  if (user.disabled) return { error: "Account disabled" };

  const ok = verifyPassword(password, user.passwordHash);
  if (!ok) return null;

  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is not configured");

  const expiresIn = process.env.JWT_EXPIRES_IN || "12h";
  const token = jwt.sign(
    { sub: doc.id, email: user.email, role: user.role },
    secret,
    { expiresIn }
  );

  return {
    token,
    user: { id: doc.id, email: user.email, role: user.role },
  };
}

module.exports = { ensureAdminBootstrap, login };
