"use strict";

const { logger } = require("../utils/logger");
const { isProd } = require("../utils/helpers");

function notFoundMiddleware(req, res) {
  res.status(404).json({ valid: false, error: "Not found" });
}

function errorMiddleware(err, req, res, next) { // eslint-disable-line no-unused-vars
  const status = err.status || err.statusCode || 500;
  const expose = !isProd() || status < 500;
  const message = expose ? (err.message || "Request failed") : "Internal server error";

  logger.error("Request error", {
    requestId: req.id,
    path: req.originalUrl,
    method: req.method,
    status,
    error: err.message,
    stack: status >= 500 ? err.stack : undefined,
  });

  res.status(status).json({ valid: false, error: message });
}

module.exports = { notFoundMiddleware, errorMiddleware };
