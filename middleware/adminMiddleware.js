"use strict";

function adminMiddleware(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ valid: false, error: "Admin privileges required" });
  }
  next();
}

module.exports = { adminMiddleware };
