require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const FRONTEND_URL = (process.env.FRONTEND_URL || "").replace(/\/$/, "");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

const VIDEO_BUCKET = "videos";
const MAX_VIDEO_SIZE = 50 * 1024 * 1024;

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is not set.");
  process.exit(1);
}

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error("ERROR: SUPABASE_URL and SUPABASE_SECRET_KEY must be set in Render.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false
  }
});

// Temporary staging only. Permanent video files live in Supabase Storage.
const UPLOAD_DIR = path.join(os.tmpdir(), "baltube-upload-staging");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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
  return Number.isSafeInteger(id) && id > 0 ? id : null;
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
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function throwIfError(result) {
  if (result.error) throw result.error;
  return result.data;
}

function videoUrl(filename) {
  return supabase.storage
    .from(VIDEO_BUCKET)
    .getPublicUrl(filename).data.publicUrl;
}

function withVideoUrl(video) {
  return {
    ...video,
    video_url: videoUrl(video.filename)
  };
}

function withUsername(row) {
  const { users, ...rest } = row;

  return {
    ...rest,
    username: users?.username || "unknown"
  };
}

function deleteTempFile(filePath) {
  if (!filePath) return;

  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.warn("Could not remove temporary upload:", error.message);
    }
  }
}

const allowedMimeTypes = new Set([
  "video/mp4",
  "video/webm",
  "video/ogg",
  "video/quicktime"
]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOAD_DIR);
  },

  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExtensions = [".mp4", ".webm", ".ogg", ".mov"];
    const safeExt = allowedExtensions.includes(ext) ? ext : "";

    cb(null, `${crypto.randomUUID()}${safeExt}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_VIDEO_SIZE
  },
  fileFilter: (_req, file, cb) => {
    if (!allowedMimeTypes.has(file.mimetype)) {
      return cb(
        new Error("Only MP4, WebM, OGG, and MOV videos are allowed.")
      );
    }

    cb(null, true);
  }
});

app.use(cors({
  origin: FRONTEND_URL || true,
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({
  extended: true,
  limit: "1mb"
}));

// Health check also verifies database access.
app.get("/health", asyncHandler(async (_req, res) => {
  const result = await supabase
    .from("users")
    .select("id", { head: true, count: "exact" })
    .limit(1);

  if (result.error) throw result.error;

  res.json({
    ok: true,
    service: "BALTube backend",
    database: "connected",
    storage: VIDEO_BUCKET
  });
}));

const transporter =
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS
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
    console.log(
      `BALTube verification URL for ${user.email}: ${verifyUrl}`
    );
    return;
  }

  await transporter.sendMail({
    from: process.env.EMAIL_FROM || process.env.SMTP_USER,
    to: user.email,
    subject: "Verify your BALTube account",

    text:
      `Welcome to BALTube!\n\n` +
      `Verify your account: ${verifyUrl}\n\n` +
      `This link expires in 24 hours.`,

    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #aaa;padding:20px">
        <h1 style="color:#c00">Welcome to BALTube!</h1>
        <p>Thanks for signing up. Click below to verify your account.</p>
        <p>
          <a href="${verifyUrl}" style="display:inline-block;background:#c00;color:#fff;padding:12px 18px;text-decoration:none;font-weight:bold">
            VERIFY MY BALTube ACCOUNT
          </a>
        </p>
        <p>This link expires in 24 hours.</p>
      </div>
    `
  });
}

// REGISTER
app.post("/api/register", asyncHandler(async (req, res) => {
  const username = cleanText(req.body.username, 24);
  const email = cleanText(req.body.email, 254).toLowerCase();
  const password = String(req.body.password || "");

  if (!validUsername(username)) {
    return res.status(400).json({
      error: "Username must be 3-24 characters and use only letters, numbers, _ or -."
    });
  }

  if (!validEmail(email)) {
    return res.status(400).json({
      error: "Please enter a valid email address."
    });
  }

  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({
      error: "Password must be between 8 and 200 characters."
    });
  }

  const existingUsername = throwIfError(
    await supabase
      .from("users")
      .select("id,username,email")
      .ilike("username", username)
      .maybeSingle()
  );

  if (existingUsername) {
    return res.status(409).json({
      error: "That username is already taken."
    });
  }

  const existingEmail = throwIfError(
    await supabase
      .from("users")
      .select("id,username,email")
      .eq("email", email)
      .maybeSingle()
  );

  if (existingEmail) {
    return res.status(409).json({
      error: "That email is already registered."
    });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  throwIfError(
    await supabase.from("users").insert({
      username,
      email,
      password: passwordHash,
      email_verified: 1,
      verification_token_hash: null,
      verification_expires: null
    })
  );

  res.status(201).json({
    message: "Account created successfully! You can now log in."
  });
}));

// VERIFY EMAIL
app.get("/api/verify-email", asyncHandler(async (req, res) => {
  const rawToken = String(req.query.token || "");

  if (!rawToken) {
    return res.status(400).send("Invalid verification link.");
  }

  const user = throwIfError(
    await supabase
      .from("users")
      .select("id,username,email,email_verified,verification_expires")
      .eq("verification_token_hash", hashToken(rawToken))
      .maybeSingle()
  );

  if (!user) {
    return res.status(400).send(
      "This verification link is invalid or has already been used."
    );
  }

  if (user.email_verified) {
    return res.send("✓ Your BALTube account is already verified.");
  }

  if (
    !user.verification_expires ||
    Date.now() > Number(user.verification_expires)
  ) {
    return res.status(400).send(
      "This verification link has expired. Please request a new one."
    );
  }

  throwIfError(
    await supabase
      .from("users")
      .update({
        email_verified: 1,
        verification_token_hash: null,
        verification_expires: null
      })
      .eq("id", user.id)
  );

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
}));

// RESEND VERIFICATION
app.post("/api/resend-verification", asyncHandler(async (req, res) => {
  const email = cleanText(req.body.email, 254).toLowerCase();

  if (!validEmail(email)) {
    return res.status(400).json({
      error: "Please enter a valid email address."
    });
  }

  const user = throwIfError(
    await supabase
      .from("users")
      .select("id,username,email,email_verified")
      .eq("email", email)
      .maybeSingle()
  );

  if (!user) {
    return res.json({
      message: "If that account exists, a new email has been sent."
    });
  }

  if (user.email_verified) {
    return res.json({
      message: "That account is already verified."
    });
  }

  const rawToken = makeToken();

  throwIfError(
    await supabase
      .from("users")
      .update({
        verification_token_hash: hashToken(rawToken),
        verification_expires: Date.now() + 24 * 60 * 60 * 1000
      })
      .eq("id", user.id)
  );

  await sendVerificationEmail(user, rawToken);

  res.json({
    message: "If that account exists, a new email has been sent."
  });
}));

// LOGIN
app.post("/api/login", asyncHandler(async (req, res) => {
  const login = cleanText(req.body.login, 254);
  const password = String(req.body.password || "");

  let user = null;

  if (login.includes("@")) {
    user = throwIfError(
      await supabase
        .from("users")
        .select("id,username,email,password,email_verified")
        .eq("email", login.toLowerCase())
        .maybeSingle()
    );
  } else {
    user = throwIfError(
      await supabase
        .from("users")
        .select("id,username,email,password,email_verified")
        .ilike("username", login)
        .maybeSingle()
    );
  }

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({
      error: "Invalid username/email or password."
    });
  }

  if (!user.email_verified) {
    return res.status(403).json({
      error: "Please verify your email before logging in."
    });
  }

  res.json({
    token: signAuthToken(user),
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    }
  });
}));

// CURRENT USER
app.get("/api/me", authRequired, asyncHandler(async (req, res) => {
  const user = throwIfError(
    await supabase
      .from("users")
      .select("id,username,email,created_at")
      .eq("id", req.user.id)
      .maybeSingle()
  );

  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  res.json(user);
}));

// UPLOAD VIDEO
app.post(
  "/api/videos",
  authRequired,
  upload.single("video"),
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "No video file was uploaded."
      });
    }

    let storedRemotely = false;

    try {
      const title = cleanText(req.body.title, 120);
      const description = cleanText(req.body.description, 5000);

      if (!title) {
        return res.status(400).json({
          error: "A video title is required."
        });
      }

      const fileBuffer = await fs.promises.readFile(req.file.path);

      const uploaded = await supabase.storage
        .from(VIDEO_BUCKET)
        .upload(req.file.filename, fileBuffer, {
          contentType: req.file.mimetype,
          upsert: false,
          cacheControl: "3600"
        });

      if (uploaded.error) throw uploaded.error;

      storedRemotely = true;

      const video = throwIfError(
        await supabase
          .from("videos")
          .insert({
            user_id: req.user.id,
            title,
            description,
            filename: req.file.filename,
            original_filename: cleanText(req.file.originalname, 255),
            mime_type: req.file.mimetype,
            views: 0
          })
          .select("id,title,description,filename,original_filename,mime_type,views,created_at,user_id")
          .single()
      );

      res.status(201).json({
        ...video,
        username: req.user.username,
        video_url: videoUrl(video.filename)
      });
    } catch (error) {
      if (storedRemotely) {
        const removal = await supabase.storage
          .from(VIDEO_BUCKET)
          .remove([req.file.filename]);

        if (removal.error) {
          console.error(
            "Could not roll back uploaded file:",
            removal.error.message
          );
        }
      }

      throw error;
    } finally {
      deleteTempFile(req.file.path);
    }
  })
);

// LIST VIDEOS
async function listVideos(orderColumn, ascending) {
  const rows = throwIfError(
    await supabase
      .from("videos")
      .select("id,title,description,filename,original_filename,mime_type,views,created_at,users(username)")
      .order(orderColumn, { ascending })
      .limit(50)
  );

  return rows.map(row => withVideoUrl(withUsername(row)));
}

app.get("/api/videos", asyncHandler(async (_req, res) => {
  res.json(await listVideos("created_at", false));
}));

app.get("/api/videos/most-viewed", asyncHandler(async (_req, res) => {
  res.json(await listVideos("views", false));
}));

// SEARCH
app.get("/api/search", asyncHandler(async (req, res) => {
  const q = cleanText(req.query.q, 100);

  if (!q) return res.json([]);

  const pattern = `%${q}%`;

  const [titleResult, descriptionResult, userResult] = await Promise.all([
    supabase
      .from("videos")
      .select("id,title,description,filename,original_filename,mime_type,views,created_at,user_id,users(username)")
      .ilike("title", pattern)
      .limit(50),

    supabase
      .from("videos")
      .select("id,title,description,filename,original_filename,mime_type,views,created_at,user_id,users(username)")
      .ilike("description", pattern)
      .limit(50),

    supabase
      .from("users")
      .select("id")
      .ilike("username", pattern)
      .limit(100)
  ]);

  const titleRows = throwIfError(titleResult);
  const descriptionRows = throwIfError(descriptionResult);
  const matchingUsers = throwIfError(userResult);

  let userVideoRows = [];

  if (matchingUsers.length) {
    userVideoRows = throwIfError(
      await supabase
        .from("videos")
        .select("id,title,description,filename,original_filename,mime_type,views,created_at,user_id,users(username)")
        .in("user_id", matchingUsers.map(user => user.id))
        .limit(50)
    );
  }

  const unique = new Map();

  [...titleRows, ...descriptionRows, ...userVideoRows].forEach(row => {
    unique.set(String(row.id), row);
  });

  const results = [...unique.values()]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 50)
    .map(row => withVideoUrl(withUsername(row)));

  res.json(results);
}));

// USER PROFILE
app.get("/api/users/:username", asyncHandler(async (req, res) => {
  const username = cleanText(req.params.username, 24);

  const user = throwIfError(
    await supabase
      .from("users")
      .select("id,username,created_at")
      .ilike("username", username)
      .maybeSingle()
  );

  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  const videos = throwIfError(
    await supabase
      .from("videos")
      .select("id,title,description,filename,mime_type,views,created_at")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
  );

  res.json({
    ...user,
    videos: videos.map(withVideoUrl)
  });
}));

// LIKE/DISLIKE TOTALS
async function getRatingTotals(videoId) {
  const rows = throwIfError(
    await supabase
      .from("ratings")
      .select("rating")
      .eq("video_id", videoId)
  );

  return rows.reduce((totals, row) => {
    if (row.rating === 1) totals.likes += 1;
    if (row.rating === -1) totals.dislikes += 1;
    return totals;
  }, {
    likes: 0,
    dislikes: 0
  });
}

// SINGLE VIDEO
app.get("/api/videos/:id", asyncHandler(async (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) {
    return res.status(400).json({ error: "Invalid video ID." });
  }

  const row = throwIfError(
    await supabase
      .from("videos")
      .select("id,title,description,filename,original_filename,mime_type,views,created_at,user_id,users(username)")
      .eq("id", id)
      .maybeSingle()
  );

  if (!row) {
    return res.status(404).json({ error: "Video not found." });
  }

  const totals = await getRatingTotals(id);

  res.json({
    ...withVideoUrl(withUsername(row)),
    likes: totals.likes,
    dislikes: totals.dislikes
  });
}));

// COUNT VIDEO VIEW
app.post("/api/videos/:id/view", asyncHandler(async (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) {
    return res.status(400).json({ error: "Invalid video ID." });
  }

  const current = throwIfError(
    await supabase
      .from("videos")
      .select("views")
      .eq("id", id)
      .maybeSingle()
  );

  if (!current) {
    return res.status(404).json({ error: "Video not found." });
  }

  const updated = throwIfError(
    await supabase
      .from("videos")
      .update({ views: Number(current.views || 0) + 1 })
      .eq("id", id)
      .select("views")
      .single()
  );

  res.json(updated);
}));

// GET COMMENTS
app.get("/api/videos/:id/comments", asyncHandler(async (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) {
    return res.status(400).json({ error: "Invalid video ID." });
  }

  const rows = throwIfError(
    await supabase
      .from("comments")
      .select("id,text,created_at,users(username)")
      .eq("video_id", id)
      .order("created_at", { ascending: true })
  );

  res.json(rows.map(withUsername));
}));

// POST COMMENT
app.post(
  "/api/videos/:id/comments",
  authRequired,
  asyncHandler(async (req, res) => {
    const id = getVideoId(req.params.id);
    const text = cleanText(req.body.text, 1000);

    if (!id) {
      return res.status(400).json({ error: "Invalid video ID." });
    }

    if (!text) {
      return res.status(400).json({
        error: "Comment cannot be empty."
      });
    }

    const video = throwIfError(
      await supabase
        .from("videos")
        .select("id")
        .eq("id", id)
        .maybeSingle()
    );

    if (!video) {
      return res.status(404).json({ error: "Video not found." });
    }

    const comment = throwIfError(
      await supabase
        .from("comments")
        .insert({
          video_id: id,
          user_id: req.user.id,
          text
        })
        .select("id,text,created_at,users(username)")
        .single()
    );

    res.status(201).json(withUsername(comment));
  })
);

// GET RATINGS
app.get("/api/videos/:id/rating", asyncHandler(async (req, res) => {
  const id = getVideoId(req.params.id);

  if (!id) {
    return res.status(400).json({ error: "Invalid video ID." });
  }

  res.json(await getRatingTotals(id));
}));

// POST RATING
app.post(
  "/api/videos/:id/rating",
  authRequired,
  asyncHandler(async (req, res) => {
    const id = getVideoId(req.params.id);
    const rating = Number(req.body.rating);

    if (!id) {
      return res.status(400).json({ error: "Invalid video ID." });
    }

    if (![1, -1].includes(rating)) {
      return res.status(400).json({
        error: "Rating must be 1 or -1."
      });
    }

    const video = throwIfError(
      await supabase
        .from("videos")
        .select("id")
        .eq("id", id)
        .maybeSingle()
    );

    if (!video) {
      return res.status(404).json({ error: "Video not found." });
    }

    throwIfError(
      await supabase
        .from("ratings")
        .upsert({
          video_id: id,
          user_id: req.user.id,
          rating
        }, {
          onConflict: "video_id,user_id"
        })
    );

    res.json(await getRatingTotals(id));
  })
);

// DELETE VIDEO
app.delete(
  "/api/videos/:id",
  authRequired,
  asyncHandler(async (req, res) => {
    const id = getVideoId(req.params.id);

    if (!id) {
      return res.status(400).json({ error: "Invalid video ID." });
    }

    const video = throwIfError(
      await supabase
        .from("videos")
        .select("id,filename,user_id")
        .eq("id", id)
        .maybeSingle()
    );

    if (!video) {
      return res.status(404).json({ error: "Video not found." });
    }

    if (String(video.user_id) !== String(req.user.id)) {
      return res.status(403).json({
        error: "You can only delete your own videos."
      });
    }

    const removedFile = await supabase.storage
      .from(VIDEO_BUCKET)
      .remove([video.filename]);

    if (removedFile.error) throw removedFile.error;

    throwIfError(
      await supabase
        .from("videos")
        .delete()
        .eq("id", id)
    );

    res.json({ message: "Video deleted." });
  })
);

// ACCOUNT RECOVERY
app.post("/api/recover-account", asyncHandler(async (req, res) => {
  const suppliedSecret = String(req.body.secret || "");

  if (
    !process.env.BAL_RECOVERY_SECRET ||
    suppliedSecret !== process.env.BAL_RECOVERY_SECRET
  ) {
    return res.status(403).json({
      error: "Recovery not authorized."
    });
  }

  const username = cleanText(req.body.username, 24);
  const newPassword = String(req.body.newPassword || "");

  if (!validUsername(username)) {
    return res.status(400).json({
      error: "Invalid username."
    });
  }

  if (newPassword.length < 8 || newPassword.length > 200) {
    return res.status(400).json({
      error: "Password must be between 8 and 200 characters."
    });
  }

  const user = throwIfError(
    await supabase
      .from("users")
      .select("id")
      .ilike("username", username)
      .maybeSingle()
  );

  if (!user) {
    return res.status(404).json({
      error: "Account not found."
    });
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);

  throwIfError(
    await supabase
      .from("users")
      .update({ password: passwordHash })
      .eq("id", user.id)
  );

  res.json({
    message: "Password reset successfully. You can now log in."
  });
}));

// ERROR HANDLING
app.use((err, _req, res, _next) => {
  console.error(
    "BALTube request error:",
    err && (err.message || err)
  );

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        error: "Video is too large. Maximum size on this BALTube storage setup is 50 MB."
      });
    }

    return res.status(400).json({ error: err.message });
  }

  if (
    err.message === "Only MP4, WebM, OGG, and MOV videos are allowed."
  ) {
    return res.status(400).json({ error: err.message });
  }

  if (err.code === "23505") {
    return res.status(409).json({
      error: "That username or email is already registered."
    });
  }

  const message = String(err.message || "");

  if (
    /payload too large|maximum allowed size|file size/i.test(message)
  ) {
    return res.status(413).json({
      error: "Video exceeds the storage upload limit. Maximum size is 50 MB on the Supabase Free plan."
    });
  }

  res.status(500).json({
    error: "Internal server error. Please check the Render logs for details."
  });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`BALTube backend running on port ${PORT}`);
  console.log("Database: Supabase PostgreSQL");
  console.log(`Video storage: Supabase Storage bucket '${VIDEO_BUCKET}'`);
  console.log(`Temporary upload staging: ${UPLOAD_DIR}`);
  console.log(`Public URL: ${PUBLIC_URL}`);
  console.log(`Frontend URL: ${FRONTEND_URL || "(CORS open)"}`);
  console.log(
    `SMTP: ${transporter ? "configured" : "not configured (verification URLs will be logged)"}`
  );
});