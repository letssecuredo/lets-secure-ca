# Let-S Secure — Backend API (Private Certificate Authority)

Production-ready Node.js + Express backend for the Let-S Secure Private Certificate Authority. Handles certificate issuance, domain verification, revocation, key management, and admin operations — all backed by Firebase Firestore.

> ⚠️ **Private CA only.** Certificates issued by this service are NOT trusted by browsers. They are valid only on systems that have installed the Let-S Secure Root CA.

[![Deploy](https://img.shields.io/badge/deploy-Render-46e3b7?style=flat-square)](https://lets-secure-ca.onrender.com)
[![Database](https://img.shields.io/badge/database-Firestore-ffa000?style=flat-square)](https://firebase.google.com/docs/firestore)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-7c3aed?style=flat-square)](#license)

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Live API](#-live-api)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Firebase Setup](#-firebase-setup)
- [Environment Variables](#-environment-variables)
- [API Reference](#-api-reference)
- [Certificate Lifecycle](#-certificate-lifecycle)
- [Private Key Handling](#-private-key-handling)
- [Domain Verification](#-domain-verification)
- [Security Model](#-security-model)
- [Deployment](#-deployment)
- [Troubleshooting](#-troubleshooting)
- [Design Decisions](#-design-decisions)
- [Changelog](#-changelog)
- [License](#license)

---

## 📖 Overview

This is the **backend API** for Let-S Secure. It provides:

- Root CA generation and secure storage
- Leaf certificate issuance via 4 verification methods
- Certificate verification, revocation, and deletion
- Encrypted private key persistence (leaf + root)
- Admin authentication and management APIs
- Immutable audit logging
- Optional merchant platform (payment links, invoices, webhooks)

The frontend (separate repository) is served from GitHub Pages and communicates with this API over HTTPS.

**Frontend repo:** https://github.com/letssecuredo/lets-secure

---

## 🌐 Live API

| Endpoint | URL |
|---|---|
| **Base URL** | https://lets-secure-ca.onrender.com |
| **Health Check** | https://lets-secure-ca.onrender.com/healthz |
| **Root CA PEM** | https://lets-secure-ca.onrender.com/api/root-ca.pem |

> ⚠️ Render free tier cold-starts take 30–60 seconds on the first request after idle.

---

## ✨ Features

### Certificate Authority
- **Root CA** — RSA-4096 self-signed, AES-256-GCM encrypted at rest
- **Leaf certificates** — RSA-2048, SHA-256 signed, 365-day validity
- **X.509 v3** — `basicConstraints`, `keyUsage`, `extKeyUsage`, `subjectAltName`, SKI/AKI
- **Wildcard support** — `*.example.com` via DNS-01
- **Real cryptography** — `node-forge` (no simulated crypto)

### Domain Verification (4 methods)
| Method | Wildcard | Instant |
|---|---|---|
| **DNS-01** — TXT record | ✅ | ❌ (5–30 min) |
| **HTTP-01** — Well-known file | ❌ | ✅ |
| **TLS-ALPN-01** — Temporary cert | ❌ | ✅ |
| **Pre-verified** — Admin whitelist | ✅ | ✅ |

### Private Key Management
- Leaf private keys **encrypted with AES-256-GCM** before storage
- Returned **once** at issuance (client must save)
- Recoverable by admin via protected endpoint
- Every key download **audit-logged**

### Management
- Certificate lifecycle (issue, verify, download, revoke, delete)
- Immutable audit log with actor, IP, timestamp
- Root CA download endpoint
- Pre-verified domain patterns (`*.company.internal`)
- Fullchain bundle (leaf + CA)

### Security
- Helmet, CORS allowlist, multi-tier rate limiting
- scrypt password hashing (timing-safe comparison)
- JWT authentication (12-hour expiry)
- Input validation on every endpoint
- Firestore rules block all client access

### Merchant Platform (Optional)
- Payment links, invoices, subscriptions
- API keys with SHA-256 hashing
- Signed webhooks with retry
- Settlement to merchant wallet

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| **Runtime** | Node.js ≥ 18 |
| **Server** | Express 4 |
| **Database** | Firebase Firestore (only) |
| **Crypto** | `node-forge` (X.509), Node `crypto` (AES-GCM, scrypt) |
| **Auth** | JWT (`jsonwebtoken`) |
| **Security** | Helmet, express-rate-limit, CORS |
| **Logging** | Morgan + structured logger |

---

## 📁 Project Structure

```
lets-secure-ca/
├── server.js
├── package.json
├── .env.example
├── .gitignore
├── README.md
│
├── firebase/
│   └── firestore.js
│
├── routes/
│   ├── index.js
│   ├── admin.routes.js
│   ├── cert.routes.js
│   ├── merchant/
│   │   ├── index.js
│   │   ├── onboarding.routes.js
│   │   ├── paymentLinks.routes.js
│   │   ├── invoices.routes.js
│   │   ├── payments.routes.js
│   │   ├── refunds.routes.js
│   │   ├── customers.routes.js
│   │   ├── apiKeys.routes.js
│   │   ├── webhooks.routes.js
│   │   ├── analytics.routes.js
│   │   └── settlements.routes.js
│   ├── public/
│   │   ├── checkout.routes.js
│   │   └── shortLink.routes.js
│   └── v1/
│       ├── index.js
│       ├── payments.routes.js
│       └── paymentLinks.routes.js
│
├── controllers/
│   ├── admin.controller.js
│   ├── cert.controller.js
│   ├── auth.controller.js
│   ├── merchant/
│   │   └── ...
│   └── public/
│       └── checkout.controller.js
│
├── middleware/
│   ├── authMiddleware.js
│   ├── adminMiddleware.js
│   ├── merchantMiddleware.js
│   ├── apiKeyMiddleware.js
│   ├── rateLimitMiddleware.js
│   ├── validationMiddleware.js
│   ├── idempotencyMiddleware.js
│   └── errorMiddleware.js
│
├── services/
│   ├── authService.js
│   ├── caService.js
│   ├── certService.js
│   ├── challengeService.js
│   ├── verifiedDomainService.js
│   ├── auditService.js
│   ├── merchantService.js
│   ├── paymentService.js
│   ├── paymentLinkService.js
│   ├── invoiceService.js
│   ├── refundService.js
│   ├── settlementService.js
│   ├── webhookService.js
│   ├── apiKeyService.js
│   ├── customerService.js
│   └── analyticsService.js
│
├── workers/
│   ├── webhookWorker.js
│   ├── settlementWorker.js
│   ├── subscriptionWorker.js
│   └── cleanupWorker.js
│
├── models/
│   └── schemas.js
│
├── utils/
│   ├── crypto.js
│   ├── helpers.js
│   └── logger.js
│
├── certificates/.gitkeep
└── logs/.gitkeep
```

---

## 🚀 Quick Start

### Prerequisites
- Node.js ≥ 18
- Firebase project with Firestore
- (Optional) Render account for deployment

### 1. Clone

```bash
git clone https://github.com/letssecuredo/lets-secure-ca.git
cd lets-secure-ca
```

### 2. Install

```bash
npm install
```

### 3. Configure

```bash
cp .env.example .env
nano .env
```

Fill in all required values (see [Environment Variables](#-environment-variables)).

### 4. Run

```bash
npm start
```

Server runs on `http://localhost:10000`.

### 5. Test

```bash
curl http://localhost:10000/healthz
# Expected: {"ok":true,"time":"..."}
```

---

## 🔥 Firebase Setup

### 1. Create project

1. Go to [Firebase Console](https://console.firebase.google.com)
2. Create a project (e.g., `lets-secure-ca`)
3. Enable **Firestore** in production mode
4. **Do NOT** enable Firebase Storage (not used)

### 2. Generate service account key

1. Project Settings → **Service accounts** → **Generate new private key**
2. Save JSON — extract:
   - `project_id` → `FIREBASE_PROJECT_ID`
   - `client_email` → `FIREBASE_CLIENT_EMAIL`
   - `private_key` → `FIREBASE_PRIVATE_KEY` (keep `\n` literal)

### 3. Create composite indexes

| Collection | Fields | Order |
|---|---|---|
| `certificates` | `issuedAt` | Descending |
| `certificates` | `domain` | Ascending |
| `certificates` | `serialNumber` | Ascending |
| `audit_logs` | `timestamp` | Descending |

Firestore will prompt with a link if an index is missing.

### 4. Firestore security rules

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

All client access blocked. Only Admin SDK can read/write.

### 5. Collections used

| Collection | Purpose |
|---|---|
| `certificates` | Leaf cert + **encrypted private key** + metadata |
| `users` | Admin accounts (scrypt hashes) |
| `revocations` | Revoked certificates |
| `audit_logs` | Immutable action log |
| `challenges` | Pending verification challenges |
| `verified_domains` | Admin whitelist patterns |
| `system` | Root CA (`root-ca` doc, encrypted) |
| `merchants` | Merchant accounts |
| `payments` | Payment records |
| `invoices` | Invoices |
| `refunds` | Refunds |
| `customers` | Customer profiles |
| `merchantApiKeys` | API keys (hashed) |
| `merchantWebhookEvents` | Webhook delivery log |

---

## 🔐 Environment Variables

Create `.env` (never commit it) based on `.env.example`.

| Variable | Description |
|---|---|
| `PORT` | HTTP port (`10000` on Render) |
| `NODE_ENV` | `production` |
| `LOG_LEVEL` | `error` \| `warn` \| `info` \| `debug` |
| `CORS_ORIGINS` | Comma-separated allowlist |
| `RATE_LIMIT_WINDOW_MS` | Global window (ms) |
| `RATE_LIMIT_MAX` | Global max requests |
| `AUTH_RATE_LIMIT_MAX` | Login attempts / 15 min |
| `ISSUE_RATE_LIMIT_MAX` | Issuance / hour |
| `JWT_SECRET` | 128 hex chars |
| `JWT_EXPIRES_IN` | e.g., `12h` |
| `MASTER_ENCRYPTION_KEY` | 64 hex chars |
| `ADMIN_EMAIL` | First admin's email |
| `ADMIN_PASSWORD` | First admin's password (min 8) |
| `FIREBASE_PROJECT_ID` | From service account JSON |
| `FIREBASE_CLIENT_EMAIL` | From service account JSON |
| `FIREBASE_PRIVATE_KEY` | From service account JSON |

### Generate secrets

```bash
# JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# MASTER_ENCRYPTION_KEY
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## 📡 API Reference

### Base URL
```
https://lets-secure-ca.onrender.com
```

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Service metadata + endpoint index |
| `GET` | `/healthz` | Liveness probe |

### Domain Verification

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/request-cert` | Request cert → returns challenge |
| `GET`  | `/api/challenge/:id` | Poll challenge status |
| `POST` | `/api/verify-challenge/:id` | Verify → issue certificate |
| `GET`  | `/api/challenge/:id/provision-cert` | TLS-ALPN-01 cert |
| `GET`  | `/api/challenge/:id/provision-key` | TLS-ALPN-01 key |

### Certificate Operations

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/verify-cert` | Verify by ID or PEM |
| `GET`  | `/api/status/:id` | Certificate metadata |
| `GET`  | `/api/cert/:id` | Download leaf PEM |
| `GET`  | `/api/cert/:id/fullchain` | Leaf + CA bundle |
| `GET`  | `/api/cert/:id/json` | JSON metadata |
| `GET`  | `/api/root-ca.pem` | Root CA PEM |

### Admin (JWT required)

| Method | Path | Description |
|---|---|---|
| `POST`   | `/api/admin/login` | Obtain JWT |
| `POST`   | `/api/admin/create-root-ca` | Generate Root CA (once) |
| `GET`    | `/api/admin/root-ca` | Root CA info |
| `GET`    | `/api/admin/certificates` | List all certificates |
| `POST`   | `/api/admin/revoke-cert` | Revoke |
| `DELETE` | `/api/admin/certificate/:id` | Delete |
| `GET`    | `/api/admin/certificate/:id/key` | **Download encrypted leaf key** |
| `GET`    | `/api/admin/verified-domains` | List whitelist |
| `POST`   | `/api/admin/verified-domains` | Add pattern |
| `DELETE` | `/api/admin/verified-domains/:id` | Remove pattern |
| `GET`    | `/api/admin/audit-logs` | Paginated audit log |

### Merchant API

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/merchant/apply` | Apply as merchant |
| `POST` | `/api/v1/payments` | Create payment (API key) |
| `POST` | `/api/merchant/payment-links` | Create link |
| `POST` | `/api/merchant/invoices` | Create invoice |
| `POST` | `/api/merchant/api-keys` | Generate key |
| `PUT`  | `/api/merchant/webhooks/settings` | Configure webhook |

---

## 🔄 Certificate Lifecycle

```
1. User submits request
        ↓
2. Is domain pre-verified?
   ├── YES → Issue + return privateKeyPem (once)
   └── NO  → Create challenge
              ↓
3. User adds DNS TXT / HTTP file / TLS cert
        ↓
4. User clicks "Verify Now"
        ↓
5. Server queries DNS / HTTP / TLS
        ↓
6. Token matches?
   ├── YES → Generate RSA-2048 keypair
   │         → Encrypt private key (AES-256-GCM)
   │         → Sign with Root CA
   │         → Store { leafCertPem, encryptedPrivateKey, metadata }
   │         → Return { certificate, privateKeyPem } (once)
   └── NO  → Return error with hints
        ↓
7. User downloads cert + fullchain + key
8. Install on server → valid for 365 days
```

### Revocation

```
Admin marks as revoked
        ↓
status: active → revoked
        ↓
Entry added to revocations/
        ↓
Verification returns { valid: false, reason: "Certificate revoked" }
```

---

## 🔑 Private Key Handling

**Private keys are handled with the same care as the Root CA.**

| Stage | What Happens |
|---|---|
| **Generation** | RSA-2048 inside `issueCertificate()` |
| **Encryption** | AES-256-GCM with `MASTER_ENCRYPTION_KEY` |
| **Storage** | `certificates/{certId}.encryptedPrivateKey` |
| **First response** | Plaintext PEM returned **once** |
| **User download** | Saves `.key.pem` from browser |
| **Admin recovery** | `GET /api/admin/certificate/:id/key` |
| **Audit** | Every download logged as `CERT_KEY_DOWNLOADED` |
| **Deletion** | Encrypted key deleted with certificate |

### Response at issuance

```json
{
  "valid": true,
  "status": "issued",
  "certificate": { "certId": "LS-5A3D8DE5", "domain": "api.example.com" },
  "privateKeyPem": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
  "warning": "Save the private key now. It will not be shown again.",
  "downloadUrl": "/api/cert/LS-5A3D8DE5",
  "fullchainUrl": "/api/cert/LS-5A3D8DE5/fullchain"
}
```

### Admin key retrieval

```bash
TOKEN=$(curl -s -X POST https://lets-secure-ca.onrender.com/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"..."}' | jq -r '.token')

curl -H "Authorization: Bearer $TOKEN" \
     -o LS-5A3D8DE5.key.pem \
     https://lets-secure-ca.onrender.com/api/admin/certificate/LS-5A3D8DE5/key
```

---

## 🎯 Domain Verification

### DNS-01

```bash
curl -X POST https://lets-secure-ca.onrender.com/api/request-cert \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "Manojit Majumdar",
    "project": "Melodyfy",
    "domain": "api.example.com",
    "email": "security@example.com",
    "method": "dns-01"
  }'
```

Response:
```json
{
  "valid": true,
  "status": "challenge_pending",
  "challenge": {
    "id": "CH-4118E9875A0A",
    "method": "dns-01",
    "dns": {
      "type": "TXT",
      "name": "_letssecure-challenge.api.example.com",
      "value": "ls-verify-a3f8b2c9...",
      "ttl": 300
    }
  }
}
```

**Add the TXT record**, wait for propagation, then verify:

```bash
curl -X POST https://lets-secure-ca.onrender.com/api/verify-challenge/CH-4118E9875A0A
```

### HTTP-01

Place a file at `/.well-known/letssecure-challenge/<token>` with the exact token content.

### TLS-ALPN-01

Install the provisioning cert on port 443 with ALPN `acme-tls/1`, then verify.

### Pre-verified

Admin whitelists a pattern → all matching domains skip the challenge.

---

## 🔒 Security Model

### Root CA Private Key
- RSA-4096, AES-256-GCM encrypted
- Never exposed via API
- Never written to disk in plaintext

### Leaf Private Keys
- RSA-2048, AES-256-GCM encrypted
- Returned once, recoverable by admin
- Audit-logged on every download

### Passwords
- scrypt (16-byte salt, 64-byte output)
- Timing-safe comparison

### JWT
- 128 hex chars secret
- 12-hour expiry
- Verified on every admin request

### Rate Limiting

| Endpoint | Limit |
|---|---|
| Global | 300 / 15 min |
| Login | 10 / 15 min |
| Issuance | 30 / hour |
| Merchant API | 100 / min per key |

### Firestore
- Rules: `allow read, write: if false`
- Only Admin SDK access
- No Firebase Storage

---

## 🚀 Deployment on Render

### 1. Push to GitHub

```bash
git add .
git commit -m "deploy"
git push
```

### 2. Create Web Service

1. Go to [dashboard.render.com](https://dashboard.render.com)
2. **New** → **Web Service**
3. Connect your repo
4. Configure:

| Field | Value |
|---|---|
| **Environment** | Node |
| **Build Command** | `npm install` |
| **Start Command** | `npm start` |
| **Health Check Path** | `/healthz` |
| **Instance Type** | Starter (recommended) |

### 3. Add environment variables

Add all from `.env.example` under **Environment**.

### 4. Deploy

Click **Save, rebuild, and deploy** — goes live in 2–3 minutes.

### 5. First-run checklist

1. ✅ `GET /healthz` returns `{"ok":true}`
2. ✅ `POST /api/admin/login` returns JWT
3. ✅ `POST /api/admin/create-root-ca` succeeds
4. ✅ Issue first certificate — verify `privateKeyPem` is returned

---

## 🐛 Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| **CORS error** | Origin missing | Add to `CORS_ORIGINS` |
| **"Root CA not initialized"** | Admin hasn't created it | Admin panel → Create Root CA |
| **"Cannot find module"** | Filename typo | Verify `require()` paths |
| **"Server auth misconfigured"** | Wrong `JWT_SECRET` | Verify 128 hex chars |
| **"MASTER_ENCRYPTION_KEY not configured"** | Wrong length | Must be 64 hex chars |
| **Firebase credential error** | Real newlines in key | Keep literal `\n` |
| **"Private key not available"** | Cert issued before encryption fix | Request new certificate |
| **"Private key could not be decrypted"** | Master key changed | Restore original key |
| **Cold start** | Render free tier | Wait 30–60s |
| **"Challenge expired"** | > 1 hour old | Request new cert |
| **"Token mismatch"** | Wrong TXT value | Copy exactly |

---

## 🧠 Design Decisions

### Why Firestore-only?
- PEM files are tiny (~2 KB)
- Atomic writes: metadata + PEM + key in one document
- Fewer moving parts, one rule set, faster reads

### Why encrypt private keys?
- Consistency with Root CA pattern
- Admin recovery if user loses key
- Compromising Firestore alone is not enough

### Why no email verification?
- Domain verification is the authoritative proof
- Email is metadata only
- Public CAs deprecated WHOIS email verification

### Why SHA-256 nonces?
- Not for blockchain, but for replay prevention
- Monotonic per wallet

---

## 📝 Changelog

### v1.2.0 — Private key handling fix
- **FIXED (critical):** Leaf private keys now encrypted + persisted
- **NEW:** `privateKeyPem` returned once at issuance
- **NEW:** Admin endpoint `GET /api/admin/certificate/:id/key`
- **NEW:** Fullchain endpoint `GET /api/cert/:id/fullchain`
- **NEW:** `CERT_KEY_DOWNLOADED` audit action
- **FIXED:** Wildcard domains accepted by `DOMAIN_RE`
- **FIXED:** Morgan uses `:res[X-Request-Id]`
- **FIXED:** `requestCert` uses `req.validated.method`
- **FIXED:** Challenge marked `USED` before issuance (no replay)

### v1.1.0 — Domain verification
- DNS-01, HTTP-01, TLS-ALPN-01 flows
- Pre-verified domains
- Advanced error classification

### v1.0.0 — Initial release
- Root CA + leaf issuance
- Admin auth + audit logs
- Firestore-only persistence

---

## 📄 License

MIT © 2025 Manojit Majumdar

---

## 📞 Support

- **Frontend Repo:** https://github.com/letssecuredo/lets-secure
- **Setup Guide:** https://letssecuredo.github.io/lets-secure/setup.html
- **Issues:** https://github.com/letssecuredo/lets-secure-ca/issues
- **Email:** gamingmanojit14@gmail.com

---

**Built with ❤️ for secure, private infrastructure.**
