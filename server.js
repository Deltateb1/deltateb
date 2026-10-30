const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "public", "uploads");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "deltateb.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  bio TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  caption TEXT NOT NULL DEFAULT '',
  filename TEXT NOT NULL,
  original_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  views INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS likes (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, video_id)
);
CREATE TABLE IF NOT EXISTS follows (
  follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  followed_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (follower_id, followed_id),
  CHECK (follower_id <> followed_id)
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 1000),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_videos_created ON videos(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id, created_at DESC);
`);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      mediaSrc: ["'self'", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "1mb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || "change-this-secret-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));
app.use(express.static(path.join(ROOT, "public"), { extensions: ["html"] }));

const authLimiter = rateLimit({ windowMs: 15 *  60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false });
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, "");
      cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`);
    }
  }),
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith("video/")) return cb(new Error("Please choose a video file."));
    cb(null, true);
  }
});

const publicUser = u => ({ id: u.id, username: u.username, displayName: u.display_name, bio: u.bio || "" });
const currentUser = req => req.session.user || null;
function requireAuth(req, res, next) {
  if (!currentUser(req)) return res.status(401).json({ error: "Please sign in first." });
  next();
}
function videoRow(row, viewerId) {
  const likeCount = db.prepare("SELECT COUNT(*) AS n FROM likes WHERE video_id=?").get(row.id).n;
  const commentCount = db.prepare("SELECT COUNT(*) AS n FROM comments WHERE video_id=?").get(row.id).n;
  const liked = viewerId ? !!db.prepare("SELECT 1 FROM likes WHERE video_id=? AND user_id=?").get(row.id, viewerId) : false;
  const following = viewerId ? !!db.prepare("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?").get(viewerId, row.user_id) : false;
  return {
    id: row.id, caption: row.caption, videoUrl: `/uploads/${encodeURIComponent(row.filename)}`,
    createdAt: row.created_at, views: row.views, likes: likeCount, comments: commentCount,
    liked, following, creator: { id: row.user_id, username: row.username, displayName: row.display_name }
  };
}

app.get("/api/me", (req, res) => {
  const user = currentUser(req);
  res.json({ user });
});

app.post("/api/register", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const displayName = String(req.body.displayName || username).trim();
  const password = String(req.body.password || "");
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: "Username must be 3–20 characters (letters, numbers or underscore)." });
  if (displayName.length < 1 || displayName.length > 40) return res.status(400).json({ error: "Display name must be 1–40 characters." });
  if (password.length < 8 || password.length > 100) return res.status(400).json({ error: "Password must contain at least 8 characters." });
  if (db.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE").get(username)) return res.status(409).json({ error: "That username is already taken." });
  const hash = await bcrypt.hash(password, 12);
  const result = db.prepare("INSERT INTO users(username,display_name,password_hash) VALUES(?,?,?)").run(username, displayName, hash);
  const user = publicUser(db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid));
  req.session.user = user;
  res.status(201).json({ user });
});

app.post("/api/login", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const row = db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(username);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) return res.status(401).json({ error: "Incorrect username or password." });
  const user = publicUser(row);
  req.session.user = user;
  res.json({ user });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/feed", (req, res) => {
  const viewer = currentUser(req);
  const mode = req.query.mode === "following" ? "following" : "foryou";
  let rows;
  if (mode === "following" && viewer) {
    rows = db.prepare(`
      SELECT v.*, u.username, u.display_name FROM videos v
      JOIN users u ON u.id=v.user_id
      JOIN follows f ON f.followed_id=v.user_id AND f.follower_id=?
      ORDER BY v.created_at DESC LIMIT 50
    `).all(viewer.id);
  } else {
    rows = db.prepare("SELECT v.*, u.username, u.display_name FROM videos v JOIN users u ON u.id=v.user_id ORDER BY v.created_at DESC LIMIT 50").all();
  }
  res.json({ videos: rows.map(r => videoRow(r, viewer && viewer.id)) });
});

app.get("/api/search", (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 50);
  if (!q) return res.json({ users: [] });
  const users = db.prepare(`
    SELECT u.id,u.username,u.display_name,
      (SELECT COUNT(*) FROM follows f WHERE f.followed_id=u.id) AS followers
    FROM users u WHERE u.username LIKE ? OR u.display_name LIKE ?
    ORDER BY followers DESC LIMIT 20
  `).all(`%${q}%`, `%${q}%`);
  res.json({ users: users.map(u => ({ id: u.id, username: u.username, displayName: u.display_name, followers: u.followers })) });
});

app.get("/api/users/:username", (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(req.params.username);
  if (!user) return res.status(404).json({ error: "User not found." });
  const viewer = currentUser(req);
  const followers = db.prepare("SELECT COUNT(*) AS n FROM follows WHERE followed_id=?").get(user.id).n;
  const following = db.prepare("SELECT COUNT(*) AS n FROM follows WHERE follower_id=?").get(user.id).n;
  const isFollowing = viewer ? !!db.prepare("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?").get(viewer.id, user.id) : false;
  const videos = db.prepare("SELECT v.*,u.username,u.display_name FROM videos v JOIN users u ON u.id=v.user_id WHERE v.user_id=? ORDER BY v.created_at DESC").all(user.id);
  res.json({ profile: { ...publicUser(user), followers, following, isFollowing }, videos: videos.map(v => videoRow(v, viewer && viewer.id)) });
});

app.post("/api/upload", requireAuth, (req, res) => {
  upload.single("video")(req, res, err => {
    if (err) return res.status(400).json({ error: err.message || "Upload failed." });
    if (!req.file) return res.status(400).json({ error: "Choose a video first." });
    const caption = String(req.body.caption || "").trim().slice(0, 300);
    const result = db.prepare("INSERT INTO videos(user_id,caption,filename,original_name) VALUES(?,?,?,?)")
      .run(req.session.user.id, caption, req.file.filename, req.file.originalname.slice(0, 255));
    res.status(201).json({ ok: true, id: result.lastInsertRowid });
  });
});

app.post("/api/videos/:id/like", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!db.prepare("SELECT id FROM videos WHERE id=?").get(id)) return res.status(404).json({ error: "Video not found." });
  const existing = db.prepare("SELECT 1 FROM likes WHERE user_id=? AND video_id=?").get(req.session.user.id, id);
  if (existing) db.prepare("DELETE FROM likes WHERE user_id=? AND video_id=?").run(req.session.user.id, id);
  else db.prepare("INSERT INTO likes(user_id,video_id) VALUES(?,?)").run(req.session.user.id, id);
  const likes = db.prepare("SELECT COUNT(*) AS n FROM likes WHERE video_id=?").get(id).n;
  res.json({ liked: !existing, likes });
});

app.post("/api/users/:id/follow", requireAuth, (req, res) => {
  const target = Number(req.params.id), me = req.session.user.id;
  if (target === me) return res.status(400).json({ error: "You cannot follow yourself." });
  if (!db.prepare("SELECT id FROM users WHERE id=?").get(target)) return res.status(404).json({ error: "User not found." });
  const existing = db.prepare("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?").get(me, target);
  if (existing) db.prepare("DELETE FROM follows WHERE follower_id=? AND followed_id=?").run(me, target);
  else db.prepare("INSERT INTO follows(follower_id,followed_id) VALUES(?,?)").run(me, target);
  res.json({ following: !existing });
});

app.get("/api/videos/:id/comments", (req, res) => {
  const id = Number(req.params.id);
  const comments = db.prepare(`
    SELECT c.id,c.body,c.created_at,u.username,u.display_name
    FROM comments c JOIN users u ON u.id=c.user_id
    WHERE c.video_id=? ORDER BY c.created_at DESC LIMIT 50
  `).all(id);
  res.json({ comments: comments.map(c => ({ id: c.id, body: c.body, createdAt: c.created_at, username: c.username, displayName: c.display_name })) });
});

app.post("/api/videos/:id/comments", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const body = String(req.body.body || "").trim();
  if (!db.prepare("SELECT id FROM videos WHERE id=?").get(id)) return res.status(404).json({ error: "Video not found." });
  if (!body || body.length > 1000) return res.status(400).json({ error: "Comment must be between 1 and 1000 characters." });
  const result = db.prepare("INSERT INTO comments(user_id,video_id,body) VALUES(?,?,?)").run(req.session.user.id, id, body);
  res.status(201).json({ id: result.lastInsertRowid });
});

app.post("/api/videos/:id/view", (req, res) => {
  const id = Number(req.params.id);
  const result = db.prepare("UPDATE videos SET views=views+1 WHERE id=?").run(id);
  if (!result.changes) return res.status(404).json({ error: "Video not found." });
  res.json({ ok: true });
});

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(ROOT, "public", "index.html"));
});

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

app.listen(PORT, () => console.log(`Deltateb is running at http://localhost:${PORT}`));
