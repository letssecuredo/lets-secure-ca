"use strict";

const crypto = require("crypto");
const dns = require("dns").promises;
const http = require("http");
const https = require("https");

const { getDb, COLLECTIONS } = require("../firebase/firestore");
const { logger } = require("../utils/logger");

const CHALLENGE_TTL_MS = 60 * 60 * 1000; // 1 hour

function newChallengeToken() {
  return "ls-verify-" + crypto.randomBytes(16).toString("hex");
}

function newChallengeId() {
  return "CH-" + crypto.randomBytes(6).toString("hex").toUpperCase();
}

/* ==========================================================
   CREATE
   ========================================================== */

async function createChallenge({ domain, owner, project, email, method = "dns-01" }) {
  const id = newChallengeId();
  const token = newChallengeToken();

  const base = {
    id,
    domain,
    owner,
    project,
    email,
    token,
    method,
    status: "pending",
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(),
    verifiedAt: null,
    usedAt: null,
    attempts: 0,
    lastError: null,
    lastAttemptAt: null,
  };

  let record;
  if (method === "dns-01") {
    record = {
      ...base,
      recordName: `_letssecure-challenge.${domain}`,
      recordValue: token,
      instructions: `Add a TXT record "${token}" at "_letssecure-challenge.${domain}" in your DNS provider.`,
    };
  } else if (method === "http-01") {
    const path = `/.well-known/letssecure-challenge/${token}`;
    record = {
      ...base,
      filePath: path,
      fileUrl: `http://${domain}${path}`,
      fileContent: token,
      instructions: `Create a file at "${path}" on your web server with the content "${token}".`,
    };
  } else {
    throw Object.assign(new Error("Unsupported challenge method"), { status: 400 });
  }

  await getDb().collection(COLLECTIONS.challenges).doc(id).set(record);
  logger.info("Challenge created", { id, domain, method });
  return record;
}

/* ==========================================================
   READ
   ========================================================== */

async function getChallengeById(id) {
  if (!id) return null;
  const snap = await getDb().collection(COLLECTIONS.challenges).doc(id).get();
  if (!snap.exists) return null;
  return { id: snap.id, ...snap.data() };
}

/* ==========================================================
   DNS-01 VERIFICATION
   ========================================================== */

async function verifyDnsChallenge(challenge) {
  let records;
  try {
    records = await dns.resolveTxt(challenge.recordName);
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA" || err.code === "ESERVFAIL") {
      throw Object.assign(
        new Error(
          `No TXT record found at "${challenge.recordName}". ` +
          `Add the record and wait 5-30 minutes for DNS propagation.`
        ),
        { status: 400, code: "DNS_NOT_FOUND" }
      );
    }
    throw Object.assign(
      new Error(`DNS lookup failed: ${err.message}`),
      { status: 400, code: "DNS_ERROR" }
    );
  }

  // TXT records come back as arrays of string chunks
  const flat = records.map((chunks) => chunks.join("").trim());
  const matched = flat.some((r) => r === challenge.token);

  if (!matched) {
    const found = flat.length ? flat.join(" | ") : "(empty)";
    throw Object.assign(
      new Error(
        `Token mismatch. Found TXT records: ${found}. Expected: ${challenge.token}`
      ),
      { status: 400, code: "DNS_MISMATCH" }
    );
  }
}

/* ==========================================================
   HTTP-01 VERIFICATION
   ========================================================== */

function fetchUrl(url, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      // Follow one redirect
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return fetchUrl(res.headers.location, timeoutMs).then(resolve, reject);
      }
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: data.trim() }));
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out after 10 seconds"));
    });
    req.on("error", reject);
  });
}

async function verifyHttpChallenge(challenge) {
  let result;
  try {
    result = await fetchUrl(challenge.fileUrl);
  } catch (err) {
    throw Object.assign(
      new Error(
        `Could not fetch ${challenge.fileUrl}: ${err.message}. ` +
        `Make sure the file exists and your server is publicly accessible on port 80.`
      ),
      { status: 400, code: "HTTP_FETCH_FAILED" }
    );
  }

  if (result.status !== 200) {
    throw Object.assign(
      new Error(`Server returned HTTP ${result.status} instead of 200`),
      { status: 400, code: "HTTP_BAD_STATUS" }
    );
  }

  if (result.body !== challenge.token) {
    throw Object.assign(
      new Error(
        `File content mismatch.\nExpected: ${challenge.token}\nFound: ${result.body || "(empty)"}`
      ),
      { status: 400, code: "HTTP_MISMATCH" }
    );
  }
}

/* ==========================================================
   VERIFY (main entry)
   ========================================================== */

async function verifyChallenge(id) {
  const challenge = await getChallengeById(id);
  if (!challenge) {
    throw Object.assign(new Error("Challenge not found"), { status: 404 });
  }
  if (new Date(challenge.expiresAt).getTime() < Date.now()) {
    throw Object.assign(
      new Error("Challenge expired. Please request a new certificate."),
      { status: 410 }
    );
  }
  if (challenge.status === "used") {
    throw Object.assign(
      new Error("This challenge has already been used to issue a certificate."),
      { status: 409 }
    );
  }
  if (challenge.status === "verified") {
    return challenge;
  }

  try {
    if (challenge.method === "dns-01") {
      await verifyDnsChallenge(challenge);
    } else if (challenge.method === "http-01") {
      await verifyHttpChallenge(challenge);
    } else {
      throw Object.assign(new Error("Unsupported challenge method"), { status: 400 });
    }
  } catch (err) {
    await getDb().collection(COLLECTIONS.challenges).doc(id).update({
      attempts: (challenge.attempts || 0) + 1,
      lastError: err.message,
      lastAttemptAt: new Date().toISOString(),
    });
    throw err;
  }

  const verifiedAt = new Date().toISOString();
  await getDb().collection(COLLECTIONS.challenges).doc(id).update({
    status: "verified",
    verifiedAt,
    attempts: (challenge.attempts || 0) + 1,
    lastError: null,
    lastAttemptAt: verifiedAt,
  });

  logger.info("Challenge verified", {
    id,
    domain: challenge.domain,
    method: challenge.method,
  });

  return { ...challenge, status: "verified", verifiedAt };
}

async function markChallengeUsed(id) {
  await getDb().collection(COLLECTIONS.challenges).doc(id).update({
    status: "used",
    usedAt: new Date().toISOString(),
  });
}

module.exports = {
  createChallenge,
  getChallengeById,
  verifyChallenge,
  markChallengeUsed,
  CHALLENGE_TTL_MS,
};
