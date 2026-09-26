"use strict";

const { getDb, COLLECTIONS } = require("../firebase/firestore");
const { buildAuditLog } = require("../models/schemas");
const { logger } = require("../utils/logger");

async function logAction({ action, actor, target, meta, ip, userAgent, success = true }) {
  try {
    const doc = buildAuditLog({ action, actor, target, meta, ip, userAgent, success });
    await getDb().collection(COLLECTIONS.auditLogs).add(doc);
  } catch (err) {
    // Audit failures must never break the request path.
    logger.error("Audit log failed", { error: err.message, action });
  }
}

async function getLogs({ limit = 100, offset = 0, action } = {}) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const safeOffset = Math.max(Number(offset) || 0, 0);

  let query = getDb()
    .collection(COLLECTIONS.auditLogs)
    .orderBy("timestamp", "desc");

  if (action) {
    query = query.where("action", "==", String(action));
  }

  const snap = await query.limit(safeLimit + safeOffset).get();
  const all = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  return all.slice(safeOffset, safeOffset + safeLimit);
}

module.exports = { logAction, getLogs };
