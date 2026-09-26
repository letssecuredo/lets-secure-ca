"use strict";

const jwt = require("jsonwebtoken");
const { getDb, COLLECTIONS } = require("../firebase/firestore");
const { logger } = require("../utils/logger");

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : null;

    if (!token) {
      return res.status(401).json({ valid: false, error: "Missing authentication token" });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      logger.error("JWT_SECRET is not configured");
      return res.status(500).json({ valid: false, error: "Server auth misconfigured" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (err) {
      return res.status(401).json({ valid: false, error: "Invalid or expired token" });
    }

    const snap = await getDb().collection(COLLECTIONS.users).doc(decoded.sub).get();
    if (!snap.exists) {
      return res.status(401).json({ valid: false, error: "User no longer exists" });
    }

    const user = snap.data();
    if (user.disabled) {
      return res.status(403).json({ valid: false, error: "Account disabled" });
    }

    req.user = {
      uid: snap.id,
      email: user.email,
      role: user.role || "admin",
    };
    next();
  } catch (err) {
    logger.error("Auth middleware error", { error: err.message });
    return res.status(500).json({ valid: false, error: "Authentication failed" });
  }
}

module.exports = { authMiddleware };
