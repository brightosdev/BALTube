require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const FRONTEND_URL = (process.env.FRONTEND_URL || "").replace(/\/$/, "");

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is not set.");
  process.exit(1);
}

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, "uploads");
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "baltube.db");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    verification_token_hash TEXT,
    verification_expires INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL UNIQUE,
    original_filename TEXT NOT NULL DEFAULT '',
    mime_type TEXT NOT NULL DEFAULT 'video/mp4',
    views INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK (rating IN (-1, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(video_id, user_id),
    FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_videos_created_at ON videos(created_at);
  CREATE INDEX IF NOT EXISTS idx_videos_views ON videos(views);
  CREATE INDEX IF NOT EXISTS idx_comments_video_id ON comments(video_id);
  CREATE INDEX IF NOT EXISTS idx_ratings_video_id ON ratings(video_id);
`);

function cleanText(value, maxLength) {
  return String(value ?? "").trim().slice(0, maxLength);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validUsername(username) {
  return /^[A-Za-z0-9_-]{3,24}$/.test(username);
}

function getVideoId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function signAuthToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Authentication required." });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

const allowedMimeTypes = new Set([
  "video/mp4",
  "video/webm",
  "video/ogg",
  "video/quicktime"
]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExtensions = [".mp4", ".webm", ".ogg", ".mov"];
    const safeExt = allowedExtensions.includes(ext) ? ext : "";
    cb(null, `${crypto.randomUUID()}${safeExt}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!allowedMimeTypes.has(file.mimetype)) {
      return cb(new Error("Only MP4, WebM, OGG, and MOV videos are allowed."));
    }
    cb(null, true);
  }
});

app.use(cors({
  origin: true
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "BALTube backend" });
});

app.use("/uploads", express.static(UPLOAD_DIR, {
  fallthrough: false,
  maxAge: "1h"
}));

const transporter =
  process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE || "false") === "true",
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      })
    : null;

async function sendVerificationEmail(user, rawToken) {
  const verifyUrl =
    `${PUBLIC_URL}/api/verify-email?token=${encodeURIComponent(rawToken)}`;

  if (!transporter) {
    console.log(`\nBALTube verification URL for ${user.email}:\n${verifyUrl}\n`);
    return;
  }

  const from = process.env.EMAIL_FROM || process.env.SMTP_USER;

  await transporter.sendMail({
    from,
    to: user.email,
    subject: "Verify your BALTube account",
    text:
      `Welcome to BALTube!\n\n` +
      `Click this link to verify your account:\n${verifyUrl}\n\n` +
      `This link expires in 24 hours.`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #aaa;padding:20px">
        <h1 style="color:#c00">Welcome to BALTube!</h1>
        <p>Thanks for signing up. Click the button below to verify your account.</p>
        <p>
          <a href="${verifyUrl}" style="display:inline-block;background:#c00;color:#fff;padding:12px 18px;text-decoration:none;font-weight:bold">
            VERIFY MY BALTube ACCOUNT
          </a>
        </p>
        <p>This verification link expires in 24 hours.</p>
      </div>
    `
  });
}

app.post("/api/register", async (req, res, next) => {
  try {
    const username = cleanText(req.body.username, 24);
    const email = cleanText(req.body.email, 254).toLowerCase();
    const password = String(req.body.password || "");

    if (!validUsername(username)) {
      return res.status(400).json({
        error: "Username must be 3-24 characters and use only letters, numbers, _ or -."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    if (password.length < 8 || password.length > 200) {
      return res.status(400).json({
        error: "Password must be between 8 and 200 characters."
      });
    }

    const existing = db.prepare(`
      SELECT id, username, email FROM users
      WHERE username = ? OR email = ?
    `).get(username, email);

    if (existing) {
      return res.status(409).json({
        error:
          existing.username.toLowerCase() === username.toLowerCase()
            ? "That username is already taken."
            : "That email is already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const rawToken = makeToken();
    const tokenHash = hashToken(rawToken);
    const expires = Date.now() + 24 * 60 * 60 * 1000;

    const result = db.prepare(`
      INSERT INTO users
        (username, email, password, email_verified, verification_token_hash, verification_expires)
      VALUES (?, ?, ?, 0, ?, ?)
    `).run(username, email, passwordHash, tokenHash, expires);

    const user = db.prepare(`
      SELECT id, username, email FROM users WHERE id = ?
    `).get(result.lastInsertRowid);

    try {
      await sendVerificationEmail(user, rawToken);
    } catch (emailError) {
      db.prepare("DELETE FROM users WHERE id = ?").run(user.id);
      console.error("Verification email failed:", emailError);
      return res.status(500).json({
        error: "The verification email could not be sent. Please try again."
      });
    }

    res.status(201).json({
      message: "Account created. Check your email to verify it."
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/verify-email", (req, res) => {
  const rawToken = String(req.query.token || "");

  if (!rawToken) return res.status(400).send("Invalid verification link.");

  const user = db.prepare(`
    SELECT id, username, email, email_verified, verification_expires
    FROM users WHERE verification_token_hash = ?
  `).get(hashToken(rawToken));

  if (!user) {
    return res.status(400).send("This verification link is invalid or has already been used.");
  }

  if (user.email_verified) {
    return res.send("✓ Your BALTube account is already verified.");
  }

  if (!user.verification_expires || Date.now() > user.verification_expires) {
    return res.status(400).send("This verification link has expired. Please request a new one.");
  }

  db.prepare(`
    UPDATE users
    SET email_verified = 1,
        verification_token_hash = NULL,
        verification_expires = NULL
    WHERE id = ?
  `).run(user.id);

  if (FRONTEND_URL) {
    return res.redirect(`${FRONTEND_URL}/?verified=1`);
  }

  res.send(`
    <html>
      <head><title>BALTube - Verified</title></head>
      <body style="font-family:Arial,sans-serif;text-align:center;padding:60px">
        <h1>✓ Email verified!</h1>
        <p>Your BALTube account is now active.</p>
        <p><a href="${PUBLIC_URL}">Enter BALTube</a></p>
      </body>
    </html>
  `);
});

app.post("/api/resend-verification", async (req, res, next) => {
  try {
    const email = cleanText(req.body.email, 254).toLowerCase();

    if (!validEmail(email)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    const user = db.prepare(`
      SELECT id, username, email, email_verified
      FROM users WHERE email = ?
    `).get(email);

    if (!user) {
      return res.json({
        message: "If that account exists, a new email has been sent."
      });
    }

    if (user.email_verified) {
      return res.json({ message: "That account is already verified." });
    }

    const rawToken = makeToken();

    db.prepare(`
      UPDATE users
      SET verification_token_hash = ?,
          verification_expires = ?
      WHERE id = ?
    `).run(hashToken(rawToken), Date.now() + 24 * 60 * 60 * 1000, user.id);

    await sendVerificationEmail(user, rawToken);

    res.json({
      message: "If that account exists, a new email has been sent."
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const login = cleanText(req.body.login, 254);
    const password = String(req.body.password || "");

    const user = db.prepare(`
      SELECT id, username, email, password, email_verified
      FROM users
      WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
    `).get(login, login);

    if (!user) {
      return res.status(401).json({ error: "Invalid username/email or password." });
    }

    const passwordOK = await bcrypt.compare(password, user.password);

    if (!passwordOK) {
      return res.status(401).json({ error: "Invalid username/email or password." });
    }

    if (!user.email_verified) {
      return res.status(403).json({
        error: "Please verify your email before logging in."
      });
    }

    const token = signAuthToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", authRequired, (req, res) => {
  const user = db.prepare(`
    SELECT id, username, email, created_at
    FROM users WHERE id = ?
  `).get(req.user.id);

  if (!user) return res.status(404).json({ error: "User not found." });

  res.json(user);
});

app.post("/api/videos", authRequired, upload.single("video"), (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No video file was uploaded." });
    }

    const title = cleanText(req.body.title, 120);
    const description = cleanText(req.body.description, 5000);

    if (!title) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "A video title is required." });
    }

    const result = db.prepare(`
      INSERT INTO videos
        (user_id, title, description, filename, original_filename, mime_type)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id,
      title,
      description,
      req.file.filename,
      cleanText(req.file.originalname, 255),
      req.file.mimetype
    );

    const video = db.prepare(`
      SELECT v.id, v.title, v.description, v.filename, v.original_filename,
             v.mime_type, v.views, v.created_at, u.username
      FROM videos v JOIN users u ON u.id = v.user_id
      WHERE v.id = ?
    `).get(result.lastInsertRowid);

    res.status(201).json({
      ...video,
      video_url: `${PUBLIC_URL}/uploads/${encodeURIComponent(video.filename)}`
    });
  } catch (error) {
    if (req.file) {
      try { fs.unlinkSync(req.file.path); } catch {}
    }
    next(error);
  }
});

app.get("/api/videos", (_req, res) => {
  const videos = db.prepare(`
    SELECT v.id, v.title, v.description, v.filename, v.original_filename,
           v.mime_type, v.views, v.created_at, u.username
    FROM videos v JOIN users u ON u.id = v.user_id
    ORDER BY v.created_at DESC
    LIMIT 50
  `).all();

  res.json(videos.map(v => ({
    ...v,
    video_url: `${PUBLIC_URL}/uploads/${encodeURIComponent(v.filename)}`
  })));
});

app.get("/api/videos/most-viewed", (_req, res) => {
  const videos = db.prepare(`
    SELECT v.id, v.title, v.description, v.filename, v.original_filename,
           v.mime_type, v.views, v.created_at, u.username
    FROM videos v JOIN users u ON u.id = v.user_id
    ORDER BY v.views DESC, v.created_at DESC
    LIMIT 50
  `).all();

  res.json(videos.map(v => ({
    ...v,
    video_url: `${PUBLIC_URL}/uploads/${encodeURIComponent(v.filename)}`
  })));
});

app.get("/api/search", (req, res) => {
  const q = cleanText(req.query.q, 100);

  if (!q) return res.json([]);

  const pattern = `%${q}%`;

  const videos = db.prepare(`
    SELECT v.id, v.title, v.description, v.filename, v.mime_type,
           v.views, v.created_at, u.username
    FROM videos v JOIN users u ON u.id = v.user_id
    WHERE v.title LIKE ?
       OR v.description LIKE ?
       OR u.username LIKE ?
    ORDER BY v.created_at DESC
    LIMIT 50
  `).all(pattern, pattern, pattern);

  res.json(videos.map(v => ({
    ...v,
    video_url: `${PUBLIC_URL}/uploads/${encodeURIComponent(v.filename)}`
  })));
});

app.get("/api/users/:username", (req, res) => {
  const username = cleanText(req.params.username, 24);

  const user = db.prepare(`
    SELECT id, username, created_at
    FROM users WHERE username = ? COLLATE NOCASE
  `).get(username);

  if (!user) return res.status(404).json({ error: "User not found." });

  const videos = db.prepare(`
    SELECT id, title, description, filename, mime_type, views, created_at
    FROM videos WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(user.id);

  res.json({
    ...user,
    videos: videos.map(v => ({
      ...v,
      video_url: `${PUBLIC_URL}/uploads/${encodeURIComponent(v.filename)}`
    }))
  });
});

app.get("/api/videos/:id", (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid video ID." });

  const video = db.prepare(`
    SELECT v.id, v.title, v.description, v.filename, v.original_filename,
           v.mime_type, v.views, v.created_at, v.user_id, u.username
    FROM videos v JOIN users u ON u.id = v.user_id
    WHERE v.id = ?
  `).get(id);

  if (!video) return res.status(404).json({ error: "Video not found." });

  const rating = db.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END), 0) AS likes,
      COALESCE(SUM(CASE WHEN rating = -1 THEN 1 ELSE 0 END), 0) AS dislikes
    FROM ratings WHERE video_id = ?
  `).get(id);

  res.json({
    ...video,
    video_url: `${PUBLIC_URL}/uploads/${encodeURIComponent(video.filename)}`,
    likes: rating.likes,
    dislikes: rating.dislikes
  });
});

app.post("/api/videos/:id/view", (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid video ID." });

  const result = db.prepare(`
    UPDATE videos SET views = views + 1 WHERE id = ?
  `).run(id);

  if (!result.changes) {
    return res.status(404).json({ error: "Video not found." });
  }

  res.json(db.prepare(`
    SELECT views FROM videos WHERE id = ?
  `).get(id));
});

app.get("/api/videos/:id/comments", (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid video ID." });

  const comments = db.prepare(`
    SELECT c.id, c.text, c.created_at, u.username
    FROM comments c JOIN users u ON u.id = c.user_id
    WHERE c.video_id = ?
    ORDER BY c.created_at ASC
  `).all(id);

  res.json(comments);
});

app.post("/api/videos/:id/comments", authRequired, (req, res) => {
  const id = getVideoId(req.params.id);
  const text = cleanText(req.body.text, 1000);

  if (!id) return res.status(400).json({ error: "Invalid video ID." });
  if (!text) return res.status(400).json({ error: "Comment cannot be empty." });

  const video = db.prepare(`
    SELECT id FROM videos WHERE id = ?
  `).get(id);

  if (!video) return res.status(404).json({ error: "Video not found." });

  const result = db.prepare(`
    INSERT INTO comments (video_id, user_id, text)
    VALUES (?, ?, ?)
  `).run(id, req.user.id, text);

  const comment = db.prepare(`
    SELECT c.id, c.text, c.created_at, u.username
    FROM comments c JOIN users u ON u.id = c.user_id
    WHERE c.id = ?
  `).get(result.lastInsertRowid);

  res.status(201).json(comment);
});

app.get("/api/videos/:id/rating", (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) return res.status(400).json({ error: "Invalid video ID." });

  const totals = db.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END), 0) AS likes,
      COALESCE(SUM(CASE WHEN rating = -1 THEN 1 ELSE 0 END), 0) AS dislikes
    FROM ratings WHERE video_id = ?
  `).get(id);

  res.json(totals);
});

app.post("/api/videos/:id/rating", authRequired, (req, res) => {
  const id = getVideoId(req.params.id);
  const rating = Number(req.body.rating);

  if (!id) return res.status(400).json({ error: "Invalid video ID." });
  if (![1, -1].includes(rating)) {
    return res.status(400).json({ error: "Rating must be 1 or -1." });
  }

  const video = db.prepare(`
    SELECT id FROM videos WHERE id = ?
  `).get(id);

  if (!video) return res.status(404).json({ error: "Video not found." });

  db.prepare(`
    INSERT INTO ratings (video_id, user_id, rating)
    VALUES (?, ?, ?)
    ON CONFLICT(video_id, user_id)
    DO UPDATE SET rating = excluded.rating
  `).run(id, req.user.id, rating);

  const totals = db.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END), 0) AS likes,
      COALESCE(SUM(CASE WHEN rating = -1 THEN 1 ELSE 0 END), 0) AS dislikes
    FROM ratings WHERE video_id = ?
  `).get(id);

  res.json(totals);
});

app.delete("/api/videos/:id", authRequired, (req, res, next) => {
  try {
    const id = getVideoId(req.params.id);

    if (!id) return res.status(400).json({ error: "Invalid video ID." });

    const video = db.prepare(`
      SELECT id, filename, user_id
      FROM videos WHERE id = ?
    `).get(id);

    if (!video) return res.status(404).json({ error: "Video not found." });

    if (video.user_id !== req.user.id) {
      return res.status(403).json({
        error: "You can only delete your own videos."
      });
    }

    db.prepare("DELETE FROM videos WHERE id = ?").run(id);

    try {
      fs.unlinkSync(path.join(UPLOAD_DIR, video.filename));
    } catch (error) {
      if (error.code !== "ENOENT") {
        console.warn("Could not delete video file:", error.message);
      }
    }

    res.json({ message: "Video deleted." });
  } catch (error) {
    next(error);
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        error: "Video is too large. Maximum size is 500 MB."
      });
    }

    return res.status(400).json({ error: err.message });
  }

  if (
    err.message === "Only MP4, WebM, OGG, and MOV videos are allowed." ||
    err.message === "CORS blocked this origin."
  ) {
    return res.status(400).json({ error: err.message });
  }

  res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, () => {
  console.log(`BALTube backend running on port ${PORT}`);
  console.log(`Database: ${DB_PATH}`);
  console.log(`Uploads: ${UPLOAD_DIR}`);
  console.log(`Public URL: ${PUBLIC_URL}`);
  console.log(`Frontend URL: ${FRONTEND_URL || "(CORS open)"}`);
  console.log(`SMTP: ${transporter ? "configured" : "not configured (verification URLs will be logged)"}`);
});
