# Let-S Secure — Private Certificate Authority

A production-ready private Certificate Authority backend for issuing, verifying, downloading, revoking and managing X.509 certificates for personal projects, internal APIs, chat applications and private services.

> **This is NOT a browser-trusted public CA.** Certificates issued by Let-S Secure are only valid for systems that trust the Let-S Secure Root CA. It is designed for private use — internal microservices, dev/staging environments, self-hosted apps, LAN services, etc.

---

## ✨ Features

- **Root CA lifecycle** — self-signed 4096-bit RSA root, AES-256-GCM encrypted at rest
- **Leaf certificate issuance** — 2048-bit RSA, SHA-256 signed, 365-day validity, SAN with wildcard
- **Real X.509 v3** — proper `basicConstraints`, `keyUsage`, `extKeyUsage`, `subjectAltName`, SKI/AKI
- **Verification** — signature, issuer, expiration window, revocation status
- **Download** — PEM bundle (`.pem`) compatible with Nginx, Apache, Traefik, Caddy, Node.js
- **Revocation** — immediate, with reason, tracked in a separate collection
- **Audit log** — every sensitive action is stored in Firestore
- **JWT admin auth** — scrypt-hashed passwords, no plaintext anywhere
- **Firestore-only storage** — no Firebase Storage, no local filesystem, zero external dependencies for data
- **Security first** — Helmet, rate limiting, CORS allowlist, input validation, error sanitisation
- **Render-ready** — `npm start`, environment-variable driven, zero local state

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js ≥ 18 |
| Server | Express 4 |
| DB | Firebase Firestore |
| Crypto | `node-forge` (X.509), `crypto` (AES-GCM, scrypt, random) |
| Auth | JWT (`jsonwebtoken`) |
| Security | Helmet, express-rate-limit, CORS |
| Logging | Morgan + custom structured logger |

> **Why `node-forge`?** Node's built-in `crypto` module does not generate or sign X.509 certificates. `node-forge` is the de-facto standard, pure-JS X.509 implementation used by thousands of production systems. The Root CA private key and all random material still come from Node's `crypto` module.

---

## 📁 Project Structure

```
backend/
├── server.js
├── package.json
├── .env.example
├── .gitignore
├── README.md
│
├── routes/
│   ├── index.js
│   ├── admin.routes.js
│   └── cert.routes.js
│
├── controllers/
│   ├── admin.controller.js
│   └── cert.controller.js
│
├── middleware/
│   ├── authMiddleware.js
│   ├── adminMiddleware.js
│   ├── errorMiddleware.js
│   ├── rateLimitMiddleware.js
│   └── validationMiddleware.js
│
├── services/
│   ├── authService.js
│   ├── caService.js
│   ├── certService.js
│   └── auditService.js
│
├── models/
│   └── schemas.js
│
├── utils/
│   ├── logger.js
│   ├── crypto.js
│   └── helpers.js
│
├── firebase/
│   └── firestore.js
│
├── certificates/.gitkeep
└── logs/.gitkeep
```

> **Note:** There is no `firebase/storage.js`. Certificate PEM and JSON payloads are stored **inline** in Firestore documents.

---

## 🔐 Environment Variables

Create a `.env` file (never commit it) based on `.env.example`.

| Variable | Description |
|---|---|
| `PORT` | HTTP port (Render sets this automatically) |
| `NODE_ENV` | `production` on Render |
| `LOG_LEVEL` | `error` \| `warn` \| `info` \| `debug` |
| `CORS_ORIGINS` | Comma-separated allowlist of origins |
| `RATE_LIMIT_WINDOW_MS` | Global rate-limit window (ms) |
| `RATE_LIMIT_MAX` | Max requests per window (global) |
| `AUTH_RATE_LIMIT_MAX` | Max login attempts per 15 minutes |
| `ISSUE_RATE_LIMIT_MAX` | Max certificate issues per hour |
| `JWT_SECRET` | 128 hex chars — `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
| `JWT_EXPIRES_IN` | e.g. `12h`, `7d` |
| `MASTER_ENCRYPTION_KEY` | 64 hex chars — `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `ADMIN_EMAIL` | First admin's email (bootstrap only) |
| `ADMIN_PASSWORD` | First admin's password (bootstrap only, min 8 chars) |
| `FIREBASE_PROJECT_ID` | From Firebase service account JSON |
| `FIREBASE_CLIENT_EMAIL` | From Firebase service account JSON |
| `FIREBASE_PRIVATE_KEY` | From Firebase service account JSON (wrap in quotes, keep `\n` literal) |

> **No `FIREBASE_STORAGE_BUCKET`** — Firebase Storage is not used.

---

## 🔥 Firebase Setup

### 1. Create a Firebase project

1. Go to <https://console.firebase.google.com>
2. Create a project (e.g. `lets-secure-ca`)
3. Enable **Firestore** in production mode

> **Storage is not required.** Skip the Firebase Storage step entirely.

### 2. Generate a service account key

1. Project Settings → **Service accounts** → **Generate new private key**
2. Copy the three fields into your `.env`:
   - `project_id` → `FIREBASE_PROJECT_ID`
   - `client_email` → `FIREBASE_CLIENT_EMAIL`
   - `private_key` → `FIREBASE_PRIVATE_KEY` (wrap in quotes; keep the `\n` sequences)

### 3. Create Firestore indexes

| Collection | Fields | Order |
|---|---|---|
| `certificates` | `issuedAt` | Descending |
| `certificates` | `domain` (asc), `issuedAt` (desc) — *optional* | — |
| `certificates` | `serialNumber` (asc) — *optional* | — |

### 4. Collections used

| Collection | Purpose |
|---|---|
| `certificates` | Leaf certificate metadata **+ PEM + JSON payload** (all inline) |
| `users` | Admin accounts (scrypt hashes) |
| `revocations` | Revoked certificate records |
| `audit_logs` | All admin and public actions |
| `system` | Root CA material (`root-ca` doc, AES-256-GCM encrypted private key) |

### 5. Storage layout inside Firestore

Everything is stored inline. A typical `certificates/{certId}` document contains:

```json
{
  "certId": "LS-1A2B3C4D",
  "serialNumber": "F3A9...",
  "owner": "Aditya Sharma",
  "project": "Nebula API",
  "domain": "api.nebula.dev",
  "email": "security@nebula.dev",
  "issuer": "Let-S Secure CA",
  "issuedAt": "2025-01-15T10:30:00.000Z",
  "expiresAt": "2026-01-15T10:30:00.000Z",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "signature": "4f9c8a...",
  "fingerprint": "4C:1B:9E:7A:...",
  "status": "active",
  "revokedAt": null,
  "revocationReason": null,
  "algorithm": "sha256WithRSA",
  "keySize": 2048,
  "leafCertPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "caCertPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "jsonPayload": { /* public JSON blob returned by the API */ }
}
```

A `system/root-ca` document contains:

```json
{
  "subject": { "commonName": "Let-S Secure Root CA", ... },
  "certPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "serialNumber": "01AB...",
  "fingerprint": "AA:BB:CC:...",
  "algorithm": "RSA-4096 / SHA-256",
  "validityDays": 3650,
  "encryptedPrivateKey": {
    "alg": "aes-256-gcm",
    "iv": "base64...",
    "tag": "base64...",
    "data": "base64..."
  },
  "createdAt": "2025-01-15T10:00:00.000Z"
}
```

> **The Root CA private key is never stored in plaintext anywhere.** It is AES-256-GCM encrypted with `MASTER_ENCRYPTION_KEY` before being written to Firestore.

---

## 📡 API Reference

Base URL: `https://let-s-secure.onrender.com`

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Service metadata + endpoint index |
| `GET` | `/healthz` | Liveness probe |

### Public

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/request-cert` | Issue a certificate |
| `POST` | `/api/verify-cert` | Verify by `certId` or `certPem` |
| `GET`  | `/api/status/:id` | Status of a certificate |
| `GET`  | `/api/cert/:id` | Download PEM bundle |
| `GET`  | `/api/cert/:id/json` | Download JSON metadata |
| `GET`  | `/api/root-ca.pem` | Download Root CA certificate (public) |

### Admin (JWT required)

| Method | Path | Description |
|---|---|---|
| `POST`   | `/api/admin/login` | Obtain JWT |
| `POST`   | `/api/admin/create-root-ca` | Generate Root CA (one-time) |
| `GET`    | `/api/admin/root-ca` | Root CA info |
| `GET`    | `/api/admin/certificates` | List all certificates |
| `POST`   | `/api/admin/revoke-cert` | Revoke a certificate |
| `DELETE` | `/api/admin/certificate/:id` | Delete a certificate |
| `GET`    | `/api/admin/audit-logs` | Paginated audit log |

### Frontend-compatible aliases

- `POST /api/certificates`
- `GET /api/certificates/:id`
- `GET /api/certificates/domain/:domain`
- `GET /api/certificates/:id/pem`

---

## 🧪 Usage Examples

### 1. Login as admin

```bash
curl -X POST https://let-s-secure.onrender.com/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"your-password"}'
```

Response:

```json
{ "valid": true, "token": "eyJhbGciOi...", "user": { "id": "...", "email": "...", "role": "admin" } }
```

### 2. Create Root CA (one time only)

```bash
curl -X POST https://let-s-secure.onrender.com/api/admin/create-root-ca \
  -H "Authorization: Bearer YOUR_TOKEN"
```

> ⚠️ **4096-bit RSA key generation takes 3–15 seconds.** If Render times the request out, retry once — the key may still have been persisted. Check `GET /api/admin/root-ca`.

### 3. Issue a certificate

```bash
curl -X POST https://let-s-secure.onrender.com/api/request-cert \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "Aditya Sharma",
    "project": "Nebula API",
    "domain": "api.nebula.dev",
    "email": "security@nebula.dev"
  }'
```

### 4. Verify a certificate

By ID:

```bash
curl -X POST https://let-s-secure.onrender.com/api/verify-cert \
  -H "Content-Type: application/json" \
  -d '{"certId":"LS-1A2B3C4D"}'
```

By raw PEM:

```bash
curl -X POST https://let-s-secure.onrender.com/api/verify-cert \
  -H "Content-Type: application/json" \
  -d "$(jq -Rs '{certPem: .}' < cert.pem)"
```

Response:

```json
{ "valid": true, "reason": "" }
```

or

```json
{ "valid": false, "reason": "Certificate revoked" }
```

### 5. Download the PEM bundle

```bash
curl -O -J https://let-s-secure.onrender.com/api/cert/LS-1A2B3C4D
```

### 6. Download the JSON metadata

```bash
curl -O -J https://let-s-secure.onrender.com/api/cert/LS-1A2B3C4D/json
```

### 7. Revoke

```bash
curl -X POST https://let-s-secure.onrender.com/api/admin/revoke-cert \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"certId":"LS-1A2B3C4D","reason":"key compromise"}'
```

---

## 🚀 Deployment on Render

1. **Push this folder to GitHub.**
2. Go to <https://dashboard.render.com> → **New** → **Web Service**.
3. Connect your GitHub repo.
4. Configure:

   | Field | Value |
   |---|---|
   | **Environment** | Node |
   | **Build Command** | `npm install` |
   | **Start Command** | `npm start` |
   | **Health Check Path** | `/healthz` |
   | **Instance Type** | Starter or higher |

5. Add **all environment variables** from `.env.example` under **Environment**.
6. Deploy.

### Generate secure secrets

```bash
# JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# MASTER_ENCRYPTION_KEY
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### First-run checklist

1. Wait for the deploy to go live.
2. `GET /` — confirm the health response.
3. `POST /api/admin/login` with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.
4. `POST /api/admin/create-root-ca` with the JWT.
5. Issue your first certificate.

---

## 🔒 Security Model

- **Root private key** is AES-256-GCM encrypted with `MASTER_ENCRYPTION_KEY` before being written to Firestore. It is **never** returned by any API.
- **Root certificate** is publicly downloadable at `GET /api/root-ca.pem`.
- **Admin passwords** are hashed with `scrypt` (16-byte salt, 64-byte output, timing-safe comparison).
- **JWT** tokens are signed with `JWT_SECRET` and expire per `JWT_EXPIRES_IN`.
- **Rate limiting** is applied globally and to sensitive endpoints (login, issuance).
- **CORS** is restricted to `CORS_ORIGINS` unless set to `*`.
- **Input validation** rejects malformed domains, emails, PEM blocks and certificate IDs before any crypto work happens.
- **Firestore** is the single source of truth. There is no Firebase Storage dependency and no local disk state.
- **Audit logs** capture every admin and public action with actor, target, IP and user-agent.

---

## 🧠 Design Notes

### Why Firestore-only (no Firebase Storage)?

- **PEM files are tiny** — a 2048-bit RSA leaf certificate is ~1.5–2 KB in PEM. Firestore's 1 MB per-document limit gives ~500× headroom.
- **Atomic writes** — certificate metadata and its PEM are written in a single Firestore operation. No risk of metadata existing without its PEM.
- **Fewer moving parts** — one Firebase product, one set of rules, one billing source.
- **Faster reads** — one document fetch instead of a metadata read + a Storage download.
- **Cheaper at low-to-medium volume** — Firestore charges per operation; Storage charges per GB stored and downloaded.

The only tradeoff: if your certificates ever exceed a few hundred KB (e.g., 8192-bit RSA), you'd approach the 1 MB document limit. For standard 2048-bit X.509 certificates, this is a non-issue.

### Why is the Root CA private key encrypted?

Firestore encryption-at-rest is handled by Google, but operators with project access could still read raw private key material. Encrypting with a separate `MASTER_ENCRYPTION_KEY` (that lives only in Render's environment variables) ensures that compromising Firestore alone is not enough to forge certificates.

### Why no private key is returned to clients

The Root CA private key and per-certificate private keys never leave the server. Only the public certificate (PEM) and public metadata (JSON) are returned. Clients receive a signed certificate — not a signing capability.

### Certificate validity window

Leaf certificates are valid for **365 days** with a 5-minute clock skew allowance on either side. The Root CA is valid for **10 years**.

### Wildcard support

If the requested domain is `api.nebula.dev`, the certificate includes SAN entries for both `api.nebula.dev` and `*.api.nebula.dev`. If you pass a wildcard directly (`*.nebula.dev`), it is used verbatim.

---

## 📝 License

MIT
