"use strict";

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const compression = require("compression");
const morgan = require("morgan");
const { v4: uuidv4 } = require("uuid");

const routes = require("./routes");
const { notFoundMiddleware, errorMiddleware } = require("./middleware/errorMiddleware");
const { generalLimiter } = require("./middleware/rateLimitMiddleware");
const { logger, morganStream } = require("./utils/logger");
const { ensureAdminBootstrap } = require("./services/authService");
const { initFirestore } = require("./firebase/firestore");

const app = express();
const PORT = process.env.PORT || 10000;

/* ---------- Trust proxy (Render) ---------- */
app.set("trust proxy", 1);
app.disable("x-powered-by");

/* ---------- Security headers ---------- */
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    referrerPolicy: { policy: "no-referrer" },
  })
);

/* ---------- CORS ---------- */
const allowedOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (
        allowedOrigins.length === 0 ||
        allowedOrigins.includes("*") ||
        allowedOrigins.includes(origin)
      ) {
        return cb(null, true);
      }
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 600,
  })
);

/* ---------- Body parsers ---------- */
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));

/* ---------- Compression ---------- */
app.use(compression());

/* ---------- Request ID ---------- */
app.use((req, res, next) => {
  req.id = uuidv4();
  res.setHeader("X-Request-Id", req.id);
  next();
});

/* ---------- HTTP logging ---------- */
app.use(
  morgan(
    ':remote-addr - :method :url :status :res[content-length] - :response-time ms "rid=:req[X-Request-Id]"',
    { stream: morganStream }
  )
);

/* ---------- Global rate limiting ---------- */
app.use(generalLimiter);

/* ---------- Routes ---------- */
app.use("/", routes);

/* ---------- 404 + error handling ---------- */
app.use(notFoundMiddleware);
app.use(errorMiddleware);

/* ---------- Bootstrap ---------- */
async function bootstrap() {
  try {
    initFirestore();
    await ensureAdminBootstrap();

    app.listen(PORT, () => {
      logger.info(`Let-S Secure CA running on port ${PORT}`, {
        env: process.env.NODE_ENV || "development",
      });
    });
  } catch (err) {
    logger.error("Bootstrap failed", { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

bootstrap();

/* ---------- Process-level safety nets ---------- */
process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled promise rejection", { reason: String(reason) });
});

process.on("uncaughtException", (err) => {
  logger.error("Uncaught exception", { error: err.message, stack: err.stack });
  process.exit(1);
});
