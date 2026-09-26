"use strict";

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const CURRENT = LEVELS[String(process.env.LOG_LEVEL || "info").toLowerCase()] ?? LEVELS.info;

function ts() {
  return new Date().toISOString();
}

function serialize(meta) {
  if (!meta) return "";
  try {
    return " " + JSON.stringify(meta);
  } catch {
    return "";
  }
}

function emit(level, message, meta) {
  if (LEVELS[level] > CURRENT) return;
  const line = `[${ts()}] [${level.toUpperCase()}] ${message}${serialize(meta)}`;
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

const logger = {
  error: (m, meta) => emit("error", m, meta),
  warn: (m, meta) => emit("warn", m, meta),
  info: (m, meta) => emit("info", m, meta),
  debug: (m, meta) => emit("debug", m, meta),
};

const morganStream = {
  write: (msg) => logger.info(msg.trim()),
};

module.exports = { logger, morganStream };
