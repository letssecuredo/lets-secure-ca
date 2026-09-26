"use strict";

const crypto = require("crypto");
const dns = require("dns").promises;
const http = require("http");
const https = require("https");
const tls = require("tls");
const forge = require("node-forge");

const { getDb, COLLECTIONS } = require("../firebase/firestore");
const { ChallengeMethod, ChallengeStatus } = require("../models/schemas");
const { logger } = require("../utils/logger");

const CHALLENGE_TTL_MS = 60 * 60 * 1000; // 1 hour
const DNS_TIMEOUT_MS = 15000;
const HTTP_TIMEOUT_MS = 10000;
const TLS_TIMEOUT_MS = 15000;

/* ==========================================================
   HELPERS
   ========================================================== */

function newChallengeToken() {
  return "ls-verify-" + crypto.randomBytes(16).toString("hex");
}

function newChallengeId() {
  return "CH-" + crypto.randomBytes(6).toString("hex").toUpperCase();
}

function generateRsaKeyPair(bits = 2048) {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits }, (err, keys) => {
      if (err) reject(err);
      else resolve(keys);
    });
  });
}

/* ==========================================================
   CREATE CHALLENGE
   ========================================================== */

async function createChallenge({ domain, owner, project, email, method = ChallengeMethod.DNS_01 }) {
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
    status: ChallengeStatus.PENDING,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(),
    verifiedAt: null,
    usedAt: null,
    attempts: 0,
    lastError: null,
    lastAttemptAt: null,
  };

  let record;

  if (method === ChallengeMethod.DNS_01) {
    record = {
      ...base,
      recordName: `_letssecure-challenge.${domain}`,
      recordValue: token,
      instructions:
        `Add a TXT record "${token}" at "_letssecure-challenge.${domain}" in your DNS provider, ` +
        `wait 5–30 minutes for propagation, then click Verify Now.`,
    };
  } else if (method === ChallengeMethod.HTTP_01) {
    const path = `/.well-known/letssecure-challenge/${token}`;
    record = {
      ...base,
      filePath: path,
      fileUrl: `http://${domain}${path}`,
      fileContent: token,
      instructions:
        `Create a file at "${path}" on your web server (must be public on port 80) ` +
        `with the exact content "${token}", then click Verify Now.`,
    };
  } else if (method === ChallengeMethod.TLS_ALPN_01) {
    const keys = await generateRsaKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = crypto.randomBytes(16).toString("hex").toUpperCase();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const attrs = [{ name: "commonName", value: domain }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: "basicConstraints", cA: false, critical: true },
      { name: "subjectAltName", altNames: [{ type: 2, value: domain }] },
      {
        name: "extensionRequest",
        extensions: [
          {
            id: "1.3.6.1.5.5.7.1.31", // id-pe-acmeIdentifier (RFC 8737)
            critical: true,
            value: forge.util.createBuffer(token, "utf8").getBytes(),
          },
        ],
      },
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    record = {
      ...base,
      alpnProtocol: "acme-tls/1",
      alpnPort: 443,
      provisionCertPem: forge.pki.certificateToPem(cert),
      provisionKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
      instructions:
        `Install the provisioning certificate on your server on port 443 with ALPN protocol "acme-tls/1", ` +
        `restart the server, then click Verify Now. Remove it after verification succeeds.`,
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
    records = await Promise.race([
      dns.resolveTxt(challenge.recordName),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("DNS lookup timed out")), DNS_TIMEOUT_MS)
      ),
    ]);
  } catch (err) {
    if (
      err.code === "ENOTFOUND" ||
      err.code === "ENODATA" ||
      err.code === "ESERVFAIL" ||
      err.code === "ETIMEOUT"
    ) {
      throw Object.assign(
        new Error(
          `No TXT record found at "${challenge.recordName}". ` +
            `Add the record and wait 5–30 minutes for DNS propagation.`
        ),
        { status: 400, code: "DNS_NOT_FOUND" }
      );
    }
    throw Object.assign(new Error(`DNS lookup failed: ${err.message}`), {
      status: 400,
      code: "DNS_ERROR",
    });
  }

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

function fetchUrl(url, timeoutMs = HTTP_TIMEOUT_MS, redirectsLeft = 3) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      if (
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location &&
        redirectsLeft > 0
      ) {
        res.resume();
        const next = res.headers.location.startsWith("http")
          ? res.headers.location
          : new URL(res.headers.location, url).toString();
        return fetchUrl(next, timeoutMs, redirectsLeft - 1).then(resolve, reject);
      }
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: data.trim() }));
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Request timed out after ${timeoutMs}ms`));
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
   TLS-ALPN-01 VERIFICATION
   ========================================================== */

async function verifyTlsAlpnChallenge(challenge) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn, arg) => {
      if (settled) return;
      settled = true;
      fn(arg);
    };

    const socket = tls.connect(
      {
        host: challenge.domain,
        port: challenge.alpnPort || 443,
        servername: challenge.domain,
        ALPNProtocols: [challenge.alpnProtocol || "acme-tls/1"],
        rejectUnauthorized: false,
        timeout: TLS_TIMEOUT_MS,
      },
      () => {
        const alpn = socket.alpnProtocol;
        const peerCert = socket.getPeerCertificate(true);
        socket.end();

        if (alpn !== (challenge.alpnProtocol || "acme-tls/1")) {
          return done(
            reject,
            Object.assign(
              new Error(
                `ALPN negotiation failed. Server returned "${alpn || "(none)"}" instead of "${challenge.alpnProtocol}". ` +
                  `Make sure your server is configured to accept the acme-tls/1 protocol.`
              ),
              { status: 400, code: "ALPN_MISMATCH" }
            )
          );
        }

        if (!peerCert || !peerCert.raw) {
          return done(
            reject,
            Object.assign(new Error("Server did not present a TLS certificate"), {
              status: 400,
              code: "NO_CERT",
            })
          );
        }

        const der = Buffer.from(peerCert.raw);
        const tokenBuf = Buffer.from(challenge.token, "utf8");
        if (der.indexOf(tokenBuf) === -1) {
          return done(
            reject,
            Object.assign(
              new Error(
                "acmeIdentifier extension not found in the served certificate. " +
                  "Make sure you installed the provisioning certificate provided below."
              ),
              { status: 400, code: "TLS_TOKEN_MISMATCH" }
            )
          );
        }

        done(resolve);
      }
    );

    socket.on("error", (err) => {
      done(
        reject,
        Object.assign(
          new Error(
            `TLS connection to ${challenge.domain}:${challenge.alpnPort || 443} failed: ${err.message}. ` +
              `Make sure your server is publicly accessible on port 443.`
          ),
          { status: 400, code: "TLS_ERROR" }
        )
      );
    });

    socket.on("timeout", () => {
      socket.destroy();
      done(
        reject,
        Object.assign(new Error("TLS connection timed out"), {
          status: 400,
          code: "TLS_TIMEOUT",
        })
      );
    });
  });
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
  if (challenge.status === ChallengeStatus.USED) {
    throw Object.assign(
      new Error("This challenge has already been used to issue a certificate."),
      { status: 409 }
    );
  }
  if (challenge.status === ChallengeStatus.VERIFIED) {
    return challenge;
  }

  try {
    if (challenge.method === ChallengeMethod.DNS_01) {
      await verifyDnsChallenge(challenge);
    } else if (challenge.method === ChallengeMethod.HTTP_01) {
      await verifyHttpChallenge(challenge);
    } else if (challenge.method === ChallengeMethod.TLS_ALPN_01) {
      await verifyTlsAlpnChallenge(challenge);
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
    status: ChallengeStatus.VERIFIED,
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

  return { ...challenge, status: ChallengeStatus.VERIFIED, verifiedAt };
}

async function markChallengeUsed(id) {
  await getDb().collection(COLLECTIONS.challenges).doc(id).update({
    status: ChallengeStatus.USED,
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
