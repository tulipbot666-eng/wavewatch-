const express = require('express');
const { WebSocketServer } = require('ws');
const { createServer } = require('http');
const { v4: uuid } = require('uuid');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Strategy: LocalStrategy } = require('passport-local');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcrypt');

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// ─────────────────────────────────────────
// DATABASE
// ─────────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error('⚠️  DATABASE_URL não definida! Configure em Render: Environment > Add Environment Variable.');
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || '',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 10
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      google_id TEXT UNIQUE,
      email TEXT UNIQUE,
      password_hash TEXT,
      name TEXT NOT NULL,
      username TEXT UNIQUE,
      avatar_emoji TEXT DEFAULT '🎬',
      avatar_url TEXT,
      profile_complete BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_seen TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_emoji TEXT DEFAULT '🎬';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_complete BOOLEAN DEFAULT FALSE;
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (LOWER(username)) WHERE username IS NOT NULL;

    CREATE TABLE IF NOT EXISTS friendships (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending', -- pending | accepted
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, friend_id)
    );

    CREATE TABLE IF NOT EXISTS session (
      sid TEXT NOT NULL COLLATE "default",
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL,
      CONSTRAINT session_pkey PRIMARY KEY (sid)
    );

    CREATE TABLE IF NOT EXISTS watch_history (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      video_url TEXT NOT NULL,
      video_title TEXT,
      video_thumb TEXT,
      video_src TEXT,
      watched_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS watch_history_user_idx ON watch_history (user_id, watched_at DESC);

    CREATE TABLE IF NOT EXISTS user_gallery (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      is_public BOOLEAN DEFAULT TRUE,
      uploaded_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS gallery_user_idx ON user_gallery (user_id, uploaded_at DESC);

    ALTER TABLE users ADD COLUMN IF NOT EXISTS banner_url TEXT;

    CREATE INDEX IF NOT EXISTS IDX_session_expire ON session (expire);

    CREATE TABLE IF NOT EXISTS user_posts (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      img_url TEXT,
      is_public BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS user_posts_user_idx ON user_posts (user_id, created_at DESC);
  `);
  // Add columns if not exist (safe migration)
    await pool.query(`ALTER TABLE user_posts ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT TRUE`).catch(()=>{});
    await pool.query(`ALTER TABLE user_posts ADD COLUMN IF NOT EXISTS img_url TEXT`).catch(()=>{});
    // Migrations
    await pool.query(`ALTER TABLE user_gallery ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT TRUE`).catch(()=>{});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS post_likes (
        id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        post_id TEXT NOT NULL REFERENCES user_posts(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, post_id)
      )
    `).catch(()=>{});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS photo_likes (
        id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        photo_id TEXT NOT NULL REFERENCES user_gallery(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, photo_id)
      )
    `).catch(()=>{});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS post_comments (
        id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        post_id TEXT NOT NULL,
        post_type TEXT NOT NULL DEFAULT 'post',
        content TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `).catch(()=>{});

    console.log('✅ Database ready');
}

initDB().catch(e => console.error('⚠️  initDB error (non-fatal):', e.message));

// ─────────────────────────────────────────
// SESSION + PASSPORT
// ─────────────────────────────────────────
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1); // necessário para cookies seguros atrás do proxy do Render

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'wavewatch-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, rows[0] || null);
  } catch(e) { done(e); }
});

// ── LOCAL STRATEGY (email + senha) ──
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = rows[0];
    if (!user || !user.password_hash) return done(null, false, { message: 'Email ou senha incorretos' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return done(null, false, { message: 'Email ou senha incorretos' });
    await pool.query('UPDATE users SET last_seen = NOW() WHERE id = $1', [user.id]);
    done(null, user);
  } catch(e) { done(e); }
}));

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const googleId = profile.id;
    const name = profile.displayName;
    const email = profile.emails?.[0]?.value || null;
    const avatarUrl = profile.photos?.[0]?.value || null;

    // Upsert user
    const { rows } = await pool.query(`
      INSERT INTO users (id, google_id, name, email, avatar_url)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (google_id) DO UPDATE SET
        name = EXCLUDED.name,
        email = EXCLUDED.email,
        avatar_url = EXCLUDED.avatar_url,
        last_seen = NOW()
      RETURNING *
    `, [uuid(), googleId, name, email, avatarUrl]);

    // Attach access token to user object for session
    const user = rows[0];
    user._googleAccessToken = accessToken;
    done(null, user);
  } catch(e) { done(e); }
}));
} // end if GOOGLE_CLIENT_ID

// ─────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email', 'https://www.googleapis.com/auth/drive.readonly'] })
  );
  app.get('/auth/google/drive',
    passport.authenticate('google', {
      scope: ['profile', 'email', 'https://www.googleapis.com/auth/drive.readonly'],
      accessType: 'offline',
      prompt: 'consent'
    })
  );
  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/?error=auth' }),
    (req, res) => {
      if (req.user._googleAccessToken) {
        req.session.googleAccessToken = req.user._googleAccessToken;
      }
      res.redirect('/');
    }
  );
} else {
  app.get('/auth/google', (req, res) => res.redirect('/?error=google_not_configured'));
  app.get('/auth/google/drive', (req, res) => res.redirect('/?error=google_not_configured'));
  app.get('/auth/google/callback', (req, res) => res.redirect('/?error=google_not_configured'));
}

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// ── EMAIL/SENHA: CADASTRO ──
app.post('/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Preencha todos os campos' });
  if (password.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length) return res.status(400).json({ error: 'Este email já está cadastrado' });
    const nameTaken = await pool.query('SELECT id FROM users WHERE LOWER(name) = LOWER($1)', [name.trim()]);
    if (nameTaken.rows.length) return res.status(400).json({ error: 'Este nome já está em uso. Escolha outro!' });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users (id, name, email, password_hash, profile_complete) VALUES ($1,$2,$3,$4,FALSE) RETURNING *',
      [uuid(), name.trim(), email.toLowerCase(), hash]
    );
    req.login(rows[0], err => {
      if (err) return res.status(500).json({ error: 'Erro ao fazer login' });
      res.json({ ok: true });
    });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

// ── EMAIL/SENHA: LOGIN ──
app.post('/auth/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.status(500).json({ error: 'Erro interno' });
    if (!user) return res.status(401).json({ error: info?.message || 'Email ou senha incorretos' });
    req.login(user, err => {
      if (err) return res.status(500).json({ error: 'Erro ao fazer login' });
      res.json({ ok: true });
    });
  })(req, res, next);
});

app.get('/auth/me', (req, res) => {
  if (!req.user) return res.json({ user: null });
  res.json({ user: {
    id: req.user.id,
    name: req.user.name,
    username: req.user.username || null,
    avatarEmoji: req.user.avatar_emoji || '🎬',
    email: req.user.email,
    avatarUrl: req.user.avatar_url,
    bannerUrl: req.user.banner_url || null,
    profileComplete: req.user.profile_complete || false,
    googleAccessToken: req.session.googleAccessToken || null
  }});
});

// ── GALLERY ──
app.get('/api/users/:id/gallery', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, url, is_public, uploaded_at FROM user_gallery WHERE user_id=$1 ORDER BY uploaded_at DESC LIMIT 50`,
      [req.params.id]
    );
    res.json({ photos: rows });
  } catch(e) { res.status(500).json({ photos: [] }); }
});

app.post('/api/gallery/upload', async (req, res) => {
  if(!req.user) return res.status(401).json({ error: 'Não autenticado' });
  const { imageData, is_public = true } = req.body;
  if(!imageData || !imageData.startsWith('data:image/')) return res.status(400).json({ error: 'Imagem inválida' });
  if(imageData.length > 10_000_000) return res.status(400).json({ error: 'Foto muito grande' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO user_gallery (user_id, url, is_public) VALUES ($1, $2, $3) RETURNING id`,
      [req.user.id, imageData, !!is_public]
    );
    res.json({ ok: true, id: rows[0].id });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

app.delete('/api/gallery/:id', async (req, res) => {
  if(!req.user) return res.status(401).json({ error: 'Não autenticado' });
  try {
    await pool.query(`DELETE FROM user_gallery WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

// ── POSTS ──
app.get('/api/users/:id/posts', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT p.id, p.content, p.created_at, u.name, u.avatar_url, u.avatar_emoji
       FROM user_posts p JOIN users u ON u.id=p.user_id
       WHERE p.user_id=$1 ORDER BY p.created_at DESC LIMIT 50`,
      [req.params.id]
    );
    res.json({ posts: rows });
  } catch(e) { res.status(500).json({ posts: [] }); }
});

// (posts route defined below)

app.delete('/api/posts/:id', async (req, res) => {
  if(!req.user) return res.status(401).json({ error: 'Não autenticado' });
  try {
    await pool.query(`DELETE FROM user_posts WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

// ── WATCH HISTORY ──
app.get('/api/users/:id/history', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT video_url, video_title, video_thumb, video_src, watched_at
       FROM watch_history WHERE user_id=$1
       ORDER BY watched_at DESC LIMIT 50`,
      [req.params.id]
    );
    res.json({ history: rows });
  } catch(e) { res.status(500).json({ history: [] }); }
});

app.get('/api/users/:id/profile', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, username, avatar_url, avatar_emoji FROM users WHERE id=$1`,
      [req.params.id]
    );
    if(!rows.length) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json({ user: rows[0] });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

// ── CHECK USERNAME AVAILABILITY ──
app.get('/api/users/check-username', async (req, res) => {
  const { username } = req.query;
  if (!username) return res.json({ available: false, error: 'Digite um username' });
  const clean = username.trim().toLowerCase();
  if (clean.length < 3) return res.json({ available: false, error: 'Mínimo 3 caracteres' });
  if (clean.length > 20) return res.json({ available: false, error: 'Máximo 20 caracteres' });
  if (!/^[a-z0-9._]+$/.test(clean)) return res.json({ available: false, error: 'Só letras, números, ponto e _' });
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE LOWER(username) = $1', [clean]);
    res.json({ available: rows.length === 0 });
  } catch(e) { res.status(500).json({ available: false, error: 'Erro interno' }); }
});

// ── SETUP PROFILE (onboarding + profile edit) ──
app.post('/auth/setup-profile', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Não autenticado' });
  const { username, avatarEmoji, displayName, avatarData, removeAvatar, bannerData } = req.body;

  const existingUsername = req.user.username;
  let finalUsername = existingUsername;

  if (username && username.trim()) {
    const clean = username.trim().toLowerCase();
    if (clean.length < 3) return res.status(400).json({ error: 'Username muito curto' });
    if (clean.length > 20) return res.status(400).json({ error: 'Username muito longo' });
    if (!/^[a-z0-9._]+$/.test(clean)) return res.status(400).json({ error: 'Username inválido' });
    const taken = await pool.query('SELECT id FROM users WHERE LOWER(username) = $1 AND id != $2', [clean, req.user.id]);
    if (taken.rows.length) return res.status(400).json({ error: 'Username já está em uso' });
    finalUsername = clean;
  }

  if (!finalUsername) return res.status(400).json({ error: 'Username obrigatório' });

  try {
    const safeName = (displayName || '').trim() || req.user.name;
    const emoji = avatarEmoji || req.user.avatar_emoji || '🎬';

    let avatarUrl = req.user.avatar_url;
    if (removeAvatar) avatarUrl = null;
    else if (avatarData && avatarData.startsWith('data:image/')) {
      if (avatarData.length > 7_000_000) return res.status(400).json({ error: 'Foto muito grande' });
      avatarUrl = avatarData;
    }

    let bannerUrl = req.user.banner_url || null;
    if (bannerData && bannerData.startsWith('data:image/')) {
      if (bannerData.length > 10_000_000) return res.status(400).json({ error: 'Banner muito grande' });
      bannerUrl = bannerData;
    }

    const { rows } = await pool.query(
      'UPDATE users SET username=$1, avatar_emoji=$2, name=$3, avatar_url=$4, banner_url=$5, profile_complete=TRUE WHERE id=$6 RETURNING *',
      [finalUsername, emoji, safeName, avatarUrl, bannerUrl, req.user.id]
    );
    req.login(rows[0], err => {
      if (err) return res.status(500).json({ error: 'Erro ao atualizar sessão' });
      res.json({ ok: true });
    });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

// ── GOOGLE DRIVE PROXY STREAM ──
app.get('/api/config', (req, res) => {
  res.json({ googleApiKey: process.env.GOOGLE_API_KEY || '' });
});

// ── PROXY REVERSO PARA IFRAME (remove X-Frame-Options) ──
app.get('/api/proxy', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send('URL required');

  try {
    const target = new URL(url);
    const proxyBase = `${req.protocol}://${req.get('host')}/api/proxy?url=`;

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'Accept-Encoding': 'identity',
        'Referer': target.origin
      },
      redirect: 'follow'
    });

    // Remove headers que bloqueiam iframe
    const headers = {};
    response.headers.forEach((val, key) => {
      const lower = key.toLowerCase();
      if (!['x-frame-options','content-security-policy','x-content-type-options'].includes(lower)) {
        headers[key] = val;
      }
    });

    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('text/html')) {
      let html = await response.text();

      // Reescreve links relativos para absolutos
      html = html
        .replace(/(href|src|action)="\/(?!\/)/g, `$1="${target.origin}/`)
        .replace(/(href|src|action)='\/(?!\/)/g, `$1='${target.origin}/`);

      // Injeta script de controle do player
      const controlScript = `
<script>
(function() {
  function findVideo() {
    return document.querySelector('video');
  }

  // Escuta comandos do WaveWatch
  window.addEventListener('message', function(e) {
    const v = findVideo();
    if (!v) return;
    if (e.data.type === 'WW_PLAY') v.play();
    if (e.data.type === 'WW_PAUSE') v.pause();
    if (e.data.type === 'WW_SEEK') v.currentTime = e.data.time;
  });

  // Envia eventos de volta para o WaveWatch
  function watch() {
    const v = findVideo();
    if (!v) { setTimeout(watch, 500); return; }
    v.addEventListener('play', () => window.parent.postMessage({type:'WW_PLAYING', time: v.currentTime}, '*'));
    v.addEventListener('pause', () => window.parent.postMessage({type:'WW_PAUSED', time: v.currentTime}, '*'));
    v.addEventListener('seeked', () => window.parent.postMessage({type:'WW_SEEKED', time: v.currentTime}, '*'));
    v.addEventListener('timeupdate', () => {
      if (Math.floor(v.currentTime) % 2 === 0)
        window.parent.postMessage({type:'WW_TIME', time: v.currentTime, duration: v.duration}, '*');
    });
    window.parent.postMessage({type:'WW_READY'}, '*');
  }
  
  if (document.readyState === 'complete') watch();
  else window.addEventListener('load', watch);
})();
</script>`;

      html = html.replace('</body>', controlScript + '</body>');
      
      Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));
      res.removeHeader('x-frame-options');
      res.removeHeader('content-security-policy');
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.send(html);
    } else {
      // Para recursos não-HTML (JS, CSS, imagens), faz proxy direto
      Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));
      const { Readable } = require('stream');
      Readable.fromWeb(response.body).on("error", ()=>{ if(!res.headersSent) res.destroy(); }).pipe(res);
    }
  } catch(e) {
    res.status(500).send('Proxy error: ' + e.message);
  }
});

app.get('/api/drive/stream/:fileId', async (req, res) => {
  const { fileId, roomId } = req.params;
  const { room: roomIdQuery } = req.query;

  // Usa token do usuário, ou do host da sala, ou fallback público
  const userToken = req.session.googleAccessToken;
  const room = roomIdQuery ? rooms.get(roomIdQuery) : null;
  const hostToken = room?.hostDriveToken || null;
  const token = userToken || hostToken;

  try {
    let driveRes;

    if (token) {
      const driveUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`;
      const fetchHeaders = { 'Authorization': `Bearer ${token}` };
      if (req.headers.range) fetchHeaders['Range'] = req.headers.range;
      driveRes = await fetch(driveUrl, { headers: fetchHeaders });
    } else {
      const driveUrl = `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`;
      const fetchHeaders = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36' };
      if (req.headers.range) fetchHeaders['Range'] = req.headers.range;
      driveRes = await fetch(driveUrl, { headers: fetchHeaders, redirect: 'follow' });
    }

    if (!driveRes.ok) {
      return res.status(driveRes.status).json({ error: `Drive returned ${driveRes.status}` });
    }

    const contentType = driveRes.headers.get('content-type') || 'video/mp4';
    if (contentType.includes('text/html')) {
      return res.status(403).json({ error: 'Drive returned HTML — file may be private or too large' });
    }

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', contentType);
    res.setHeader('Accept-Ranges', 'bytes');
    const contentLength = driveRes.headers.get('content-length');
    const contentRange = driveRes.headers.get('content-range');
    if (contentLength) res.setHeader('Content-Length', contentLength);
    if (contentRange) res.setHeader('Content-Range', contentRange);
    res.status(driveRes.status);
    const { Readable } = require('stream');
    Readable.fromWeb(driveRes.body).on("error", ()=>{ if(!res.headersSent) res.destroy(); }).pipe(res);
  } catch(e) {
    console.error('Drive proxy error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────
// FRIENDS API
// ─────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// Search users by name or username
app.get('/api/users/search', requireAuth, async (req, res) => {
  const q = req.query.q?.trim();
  if (!q) return res.json({ users: [] });
  try {
    const { rows } = await pool.query(`
      SELECT id, name, username, avatar_url, avatar_emoji FROM users
      WHERE (name ILIKE $1 OR username ILIKE $1) AND id != $2
      LIMIT 10
    `, [`%${q}%`, req.user.id]);
    res.json({ users: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Send friend request
app.post('/api/friends/request', requireAuth, async (req, res) => {
  const { friendId } = req.body;
  if (!friendId || friendId === req.user.id) return res.status(400).json({ error: 'Invalid' });
  try {
    await pool.query(`
      INSERT INTO friendships (user_id, friend_id, status)
      VALUES ($1, $2, 'pending')
      ON CONFLICT DO NOTHING
    `, [req.user.id, friendId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Accept friend request
app.post('/api/friends/accept', requireAuth, async (req, res) => {
  const { friendId } = req.body;
  try {
    // Accept the incoming request
    await pool.query(`
      UPDATE friendships SET status = 'accepted'
      WHERE user_id = $1 AND friend_id = $2
    `, [friendId, req.user.id]);
    // Create reverse entry
    await pool.query(`
      INSERT INTO friendships (user_id, friend_id, status)
      VALUES ($1, $2, 'accepted')
      ON CONFLICT (user_id, friend_id) DO UPDATE SET status = 'accepted'
    `, [req.user.id, friendId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Remove / reject friend
app.delete('/api/friends/:friendId', requireAuth, async (req, res) => {
  const { friendId } = req.params;
  try {
    await pool.query(`DELETE FROM friendships WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)`, [req.user.id, friendId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// List friends (accepted + pending sent)
app.get('/api/friends', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.name, u.username, u.avatar_url, u.avatar_emoji, f.status
      FROM friendships f
      JOIN users u ON u.id = f.friend_id
      WHERE f.user_id = $1
      ORDER BY f.status, u.name
    `, [req.user.id]);
    res.json({ friends: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Pending requests received
app.get('/api/friends/pending', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.name, u.username, u.avatar_url, u.avatar_emoji
      FROM friendships f
      JOIN users u ON u.id = f.user_id
      WHERE f.friend_id = $1 AND f.status = 'pending'
    `, [req.user.id]);
    res.json({ pending: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// POSTS API
// ─────────────────────────────────────────
app.post('/api/posts', requireAuth, async (req, res) => {
  const { content, is_public = true, img_url } = req.body;
  if(!content?.trim() && !img_url) return res.status(400).json({ error: 'Conteúdo vazio' });
  if(content && content.length > 1000) return res.status(400).json({ error: 'Post muito longo (máx 1000 caracteres)' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO user_posts (user_id, content, is_public, img_url) VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.user.id, (content||'').trim(), !!is_public, img_url||null]
    );
    res.json({ ok: true, post: rows[0] });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

app.get('/api/users/:id/posts', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT p.id, p.content, p.img_url, p.is_public, p.created_at, u.id as user_id, u.name, u.username, u.avatar_url, u.avatar_emoji
       FROM user_posts p JOIN users u ON u.id = p.user_id
       WHERE p.user_id = $1 ORDER BY p.created_at DESC LIMIT 50`,
      [req.params.id]
    );
    res.json({ posts: rows });
  } catch(e) { res.status(500).json({ posts: [] }); }
});

// Feed: public posts from everyone OR friends
app.get('/api/feed', async (req, res) => {
  const type = req.query.type || 'public'; // 'public' | 'friends'
  try {
    let rows;
    if (type === 'friends' && req.user) {
      const { rows: r } = await pool.query(
        `SELECT p.id, p.content, p.img_url, p.is_public, p.created_at, u.id as user_id, u.name, u.username, u.avatar_url, u.avatar_emoji
         FROM user_posts p JOIN users u ON u.id = p.user_id
         WHERE (u.id = $1 OR u.id IN (
           SELECT CASE WHEN user_id=$1 THEN friend_id ELSE user_id END
           FROM friendships WHERE (user_id=$1 OR friend_id=$1) AND status='accepted'
         ))
         ORDER BY p.created_at DESC LIMIT 80`,
        [req.user.id]
      );
      rows = r;
    } else {
      const { rows: r } = await pool.query(
        `SELECT p.id, p.content, p.img_url, p.is_public, p.created_at, u.id as user_id, u.name, u.username, u.avatar_url, u.avatar_emoji
         FROM user_posts p JOIN users u ON u.id = p.user_id
         WHERE p.is_public = TRUE
         ORDER BY p.created_at DESC LIMIT 80`
      );
      rows = r;
    }
    res.json({ posts: rows });
  } catch(e) { res.status(500).json({ posts: [] }); }
});

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM user_posts WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

// ─────────────────────────────────────────
// ROOM STATE
// ─────────────────────────────────────────
const rooms = new Map();

function getOrCreateRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      id: roomId,
      name: null,
      isPublic: false,
      category: null,
      host: null,
      hostName: null,
      members: new Map(),
      video: null,
      queue: [],
      playing: false,
      currentTime: 0,
      wallClock: Date.now(),
      history: [],
      createdAt: Date.now()
    });
  }
  return rooms.get(roomId);
}

function getProjectedTime(room) {
  if (!room.playing) return room.currentTime;
  return room.currentTime + (Date.now() - room.wallClock) / 1000;
}

function roomInfo(room) {
  return {
    id: room.id,
    hostDriveToken: room.hostDriveToken || null,
    name: room.name,
    isPublic: room.isPublic,
    category: room.category,
    host: room.host,
    hostName: room.hostName,
    members: [...room.members.values()].map(m => m.user),
    memberCount: room.members.size,
    video: room.video,
    queue: room.queue,
    playing: room.playing,
    currentTime: getProjectedTime(room),
    wallClock: room.wallClock,
    serverNow: Date.now(),
    history: room.history.slice(-20)
  };
}

function broadcast(room, msg, excludeId = null) {
  const data = JSON.stringify(msg);
  room.members.forEach((member, id) => {
    if (id !== excludeId && member.ws.readyState === 1) member.ws.send(data);
  });
}

function broadcastAll(room, msg) { broadcast(room, msg, null); }

function sendStateToMember(room, member, msgType) {
  if (member.ws.readyState !== 1) return;
  const rtt = member.rtt || 80;
  const projected = getProjectedTime(room);
  const compensated = projected + (room.playing ? rtt / 2000 : 0);
  member.ws.send(JSON.stringify({
    type: msgType || 'SYNC_TICK',
    payload: { playing: room.playing, currentTime: compensated, wallClock: room.wallClock, serverNow: Date.now() }
  }));
}

// ─────────────────────────────────────────
// WEBSOCKET
// ─────────────────────────────────────────
wss.on('connection', (ws) => {
  const wsId = uuid();
  let currentRoom = null;
  let currentUser = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const { type, payload } = msg;

    if (type === 'JOIN') {
      const { roomId, user, roomName, isPublic, category, driveToken } = payload;
      currentUser = { ...user, id: wsId, joinedAt: Date.now() };
      currentRoom = getOrCreateRoom(roomId);
      if (currentRoom.members.size === 0) {
        currentRoom.host = wsId;
        currentRoom.hostName = user.name;
        currentUser.isHost = true;
        // Salva token do host para usar no Drive
        if (driveToken) currentRoom.hostDriveToken = driveToken;
        // Set room metadata on creation
        if (roomName) currentRoom.name = roomName;
        if (isPublic !== undefined) currentRoom.isPublic = !!isPublic;
        if (category) currentRoom.category = category;
      }
      currentRoom.members.set(wsId, { ws, user: currentUser, rtt: 80 });
      const state = roomInfo(currentRoom);
      state.myWsId = wsId;
      ws.send(JSON.stringify({ type: 'ROOM_STATE', payload: state }));
      broadcast(currentRoom, { type: 'USER_JOINED', payload: { user: currentUser, memberCount: currentRoom.members.size } }, wsId);
    }

    if (type === 'HOST_TOKEN' && currentRoom) {
      // Host atualiza token do Drive na sala
      if (currentRoom.host === wsId && payload.driveToken) {
        currentRoom.hostDriveToken = payload.driveToken;
      }
    }

    if (type === 'PING') {
      const now = Date.now();
      ws.send(JSON.stringify({ type: 'PONG', payload: { ts: payload.ts, serverNow: now } }));
      const member = currentRoom?.members.get(wsId);
      if (member) {
        const measured = now - payload.ts;
        if (!member.rttSamples) member.rttSamples = [];
        member.rttSamples.push(measured);
        if (member.rttSamples.length > 5) member.rttSamples.shift();
        member.rtt = Math.min(...member.rttSamples);
      }
    }

    if (type === 'CLIENT_TIME' && currentRoom) {
      const member = currentRoom.members.get(wsId);
      if (member) {
        member.clientTime = payload.currentTime;
        member.clientTimeAt = Date.now();
        member.clientPlaying = payload.playing;
      }
    }

    if (type === 'CHAT' && currentRoom) {
      const imgData = payload.imgData && payload.imgData.length < 7_000_000 ? payload.imgData : null;
      const gifUrl = payload.gifUrl || null;
      // Manda pra todos EXCETO o remetente (ele já renderizou localmente)
      broadcast(currentRoom, { type: 'CHAT', payload: { id: uuid(), user: currentUser, text: payload.text || '', gifUrl, imgData, ts: Date.now() } }, wsId);
    }

    if (type === 'REACTION' && currentRoom) {
      broadcastAll(currentRoom, { type: 'REACTION', payload: { emoji: payload.emoji, user: currentUser, ts: Date.now() } });
    }

    if (type === 'VIDEO' && currentRoom) {
      currentRoom.video = payload.video;
      currentRoom.playing = false;
      currentRoom.currentTime = 0;
      currentRoom.wallClock = Date.now();
      // Salva no histórico pessoal do usuário (se tiver dbId)
      if (payload.video && currentUser.dbId) {
        pool.query(
          `INSERT INTO watch_history (user_id, video_url, video_title, video_thumb, video_src)
           VALUES ($1,$2,$3,$4,$5)`,
          [currentUser.dbId, payload.video.url||'', payload.video.title||'', payload.video.thumb||'', payload.video.src||'']
        ).catch(()=>{});
      }
      if (payload.video) {
        currentRoom.history.unshift({
          url: payload.video.url || '',
          title: payload.video.title || '',
          thumb: payload.video.thumb || '',
          src: payload.video.src || '',
          addedBy: currentUser.name
        });
        if (currentRoom.history.length > 50) currentRoom.history.pop();
      }
      broadcastAll(currentRoom, { type: 'VIDEO', payload: { video: payload.video, by: currentUser } });
    }

    if (type === 'QUEUE_UPDATE' && currentRoom) {
      currentRoom.queue = payload.queue;
      broadcastAll(currentRoom, { type: 'QUEUE_UPDATE', payload: { queue: currentRoom.queue, by: currentUser } });
    }

    if (type === 'STATE' && currentRoom) {
      const hostRtt = currentRoom.members.get(wsId)?.rtt || 80;
      const trueTime = payload.currentTime + (payload.playing ? hostRtt / 2000 : 0);
      currentRoom.playing = payload.playing;
      currentRoom.currentTime = trueTime;
      currentRoom.wallClock = Date.now();
      currentRoom.members.forEach((member, id) => {
        if (id === wsId || member.ws.readyState !== 1) return;
        sendStateToMember(currentRoom, member, 'STATE');
      });
    }

    if (type === 'SEEK' && currentRoom) {
      const hostRtt = currentRoom.members.get(wsId)?.rtt || 80;
      const trueTime = payload.t + (currentRoom.playing ? hostRtt / 2000 : 0);
      currentRoom.currentTime = trueTime;
      currentRoom.wallClock = Date.now();
      currentRoom.members.forEach((member, id) => {
        if (id === wsId || member.ws.readyState !== 1) return;
        const compensated = trueTime + (currentRoom.playing ? (member.rtt || 80) / 2000 : 0);
        member.ws.send(JSON.stringify({ type: 'SEEK', payload: { t: compensated } }));
      });
    }

    // ── WebRTC SCREEN SHARE SIGNALING ──────────────────────
    if (type === 'SCREEN_SHARE_START' && currentRoom) {
      currentRoom.screenShareHost = wsId;
      broadcast(currentRoom, { type: 'SCREEN_SHARE_START', payload: { by: currentUser } }, wsId);
    }

    if (type === 'SCREEN_SHARE_STOP' && currentRoom) {
      currentRoom.screenShareHost = null;
      broadcastAll(currentRoom, { type: 'SCREEN_SHARE_STOP', payload: {} });
    }

    // Targeted relay: host → specific viewer or viewer → host
    if ((type === 'WR_OFFER' || type === 'WR_ANSWER' || type === 'WR_ICE') && currentRoom) {
      const target = currentRoom.members.get(payload.targetId);
      if (target && target.ws.readyState === 1) {
        target.ws.send(JSON.stringify({
          type,
          payload: { ...payload, fromId: wsId }
        }));
      }
    }
  });

  ws.on('close', () => {
    if (!currentRoom) return;
    currentRoom.members.delete(wsId);
    if (currentRoom.host === wsId && currentRoom.members.size > 0) {
      const newHostId = currentRoom.members.keys().next().value;
      currentRoom.host = newHostId;
      const newHostMember = currentRoom.members.get(newHostId);
      if (newHostMember) {
        newHostMember.user.isHost = true;
        broadcastAll(currentRoom, { type: 'HOST_CHANGED', payload: { hostId: newHostId } });
      }
    }
    if (currentRoom.members.size === 0) {
      setTimeout(() => { if (rooms.get(currentRoom.id)?.members.size === 0) rooms.delete(currentRoom.id); }, 60000);
    }
    broadcast(currentRoom, { type: 'USER_LEFT', payload: { user: currentUser, memberCount: currentRoom.members.size } });
  });
});

// ─────────────────────────────────────────
// REST API
// ─────────────────────────────────────────
app.get('/api/room/new', requireAuth, (req, res) => {
  res.json({ roomId: generateRoomCode() });
});

app.get('/api/room/:id', (req, res) => {
  const room = rooms.get(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  res.json({ exists: true, memberCount: room.members.size });
});

// Public rooms listing
app.get('/api/rooms/public', (req, res) => {
  const category = req.query.category;
  const list = [];
  rooms.forEach(room => {
    if (!room.isPublic || room.members.size === 0) return;
    if (category && category !== 'all' && room.category !== category) return;
    list.push({
      id: room.id,
      name: room.name || room.id,
      category: room.category || 'geral',
      hostName: room.hostName,
      memberCount: room.members.size,
      video: room.video ? { title: room.video.title, thumb: room.video.thumb, src: room.video.src } : null,
      playing: room.playing,
      createdAt: room.createdAt
    });
  });
  // Sort by member count desc
  list.sort((a, b) => b.memberCount - a.memberCount);
  res.json({ rooms: list });
});

app.get('/api/yt/trending', async (req, res) => {
  // Helper recursivo — funciona pra qualquer estrutura InnerTube
  function extractVideos(obj, items, max = 20) {
    if (!obj || typeof obj !== 'object' || items.length >= max) return;
    if (Array.isArray(obj)) { for (const x of obj) extractVideos(x, items, max); return; }
    if (obj.videoRenderer?.videoId) {
      const v = obj.videoRenderer;
      items.push({
        id: v.videoId,
        title: v.title?.runs?.[0]?.text || '',
        duration: v.lengthText?.simpleText || '',
        thumb: 'https://i.ytimg.com/vi/' + v.videoId + '/hqdefault.jpg',
        views: v.viewCountText?.simpleText || v.shortViewCountText?.simpleText || '',
        published: v.publishedTimeText?.simpleText || ''
      });
      return;
    }
    for (const val of Object.values(obj)) extractVideos(val, items, max);
  }

  const innertube = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-YouTube-Client-Name': '1',
      'X-YouTube-Client-Version': '2.20240101.00.00',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0'
    }
  };

  // Tenta 1: browse FEtrending WEB
  try {
    const r = await fetch('https://www.youtube.com/youtubei/v1/browse?prettyPrint=false', {
      ...innertube,
      body: JSON.stringify({
        browseId: 'FEwhat_to_watch',
        context: { client: { clientName: 'WEB', clientVersion: '2.20240101.00.00', hl: 'pt', gl: 'BR' } }
      })
    });
    if (r.ok) {
      const data = await r.json();
      const items = [];
      extractVideos(data?.contents, items);
      if (items.length > 0) { console.log('[home] InnerTube OK:', items.length); return res.json({ items }); }
      console.log('[home] returned 0 items, trying fallback');
    }
  } catch (e) { console.error('[trending] InnerTube error:', e.message); }

  // Fallback: busca por "trending brasil" via search
  try {
    const r2 = await fetch('https://www.youtube.com/youtubei/v1/search?prettyPrint=false', {
      ...innertube,
      body: JSON.stringify({
        query: 'trending brasil 2025',
        context: { client: { clientName: 'WEB', clientVersion: '2.20240101.00.00', hl: 'pt', gl: 'BR' } }
      })
    });
    if (r2.ok) {
      const data2 = await r2.json();
      const items2 = [];
      extractVideos(data2?.contents, items2);
      console.log('[trending] fallback search:', items2.length);
      return res.json({ items: items2 });
    }
  } catch (e) { console.error('[trending] fallback error:', e.message); }

  res.json({ items: [] });
});

app.get('/api/yt/search', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json({ items: [] });
  try {
    // InnerTube API — retorna resultados reais com thumbnail, titulo, canal, duracao
    const r = await fetch('https://www.youtube.com/youtubei/v1/search?prettyPrint=false', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-YouTube-Client-Name': '1',
        'X-YouTube-Client-Version': '2.20240101.00.00',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      body: JSON.stringify({
        query: q,
        context: {
          client: {
            clientName: 'WEB',
            clientVersion: '2.20240101.00.00',
            hl: 'pt',
            gl: 'BR'
          }
        }
      })
    });
    const data = await r.json();

    const contents =
      data?.contents?.twoColumnSearchResultsRenderer?.primaryContents
           ?.sectionListRenderer?.contents?.[0]
           ?.itemSectionRenderer?.contents || [];

    const items = [];
    for (const c of contents) {
      const v = c.videoRenderer;
      if (!v || !v.videoId) continue;
      const title    = v.title?.runs?.[0]?.text || '';
      const channel  = v.ownerText?.runs?.[0]?.text || v.longBylineText?.runs?.[0]?.text || '';
      const duration = v.lengthText?.simpleText || '';
      const thumb    = `https://i.ytimg.com/vi/${v.videoId}/hqdefault.jpg`;
      const views    = v.viewCountText?.simpleText || v.shortViewCountText?.simpleText || '';
      const published = v.publishedTimeText?.simpleText || '';
      const channelAvatar = v.channelThumbnailSupportedRenderers
        ?.channelThumbnailWithLinkRenderer?.thumbnail?.thumbnails?.[0]?.url || '';
      items.push({ id: v.videoId, title, channel, duration, thumb, views, published, channelAvatar });
      if (items.length >= 12) break;
    }

    res.json({ items });
  } catch (e) {
    console.error('YT search error:', e.message);
    res.json({ items: [] });
  }
});

app.get('/api/yt/info', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'No URL' });
  try {
    const r = await fetch(`https://www.youtube.com/oembed?url=${encodeURIComponent(url)}&format=json`);
    if (!r.ok) throw new Error('Not found');
    const data = await r.json();
    res.json({ title: data.title, thumb: data.thumbnail_url, author: data.author_name });
  } catch (e) { res.status(404).json({ error: 'Video not found' }); }
});

// ─────────────────────────────────────────
// YT-DLP EXTRACT + STREAM PROXY
// ─────────────────────────────────────────
const { exec } = require('child_process');


// Extrai URL direta do stream usando yt-dlp


// Proxy de stream — repassa o vídeo/HLS com headers corretos
const YT_DLP = process.env.YT_DLP_PATH || 'yt-dlp';

// Cache de URLs extraídas — TTL 4 minutos
const streamCache = new Map();
const STREAM_CACHE_TTL = 4 * 60 * 1000;

async function scrapeTokyvideo(pageUrl) {
  const cached = streamCache.get(pageUrl);
  if (cached && Date.now() - cached.ts < STREAM_CACHE_TTL) return cached;

  const r = await fetch(pageUrl, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
      'Accept': 'text/html,*/*',
      'Accept-Language': 'pt-BR,pt;q=0.9',
    }
  });
  const html = await r.text();
  const m = html.match(/https:\/\/cdnst\d*\.tokyvideo\.com\/[^"'\s<>]+\.mp4[^"'\s<>]*/);
  if (!m) throw new Error('URL do stream não encontrada');
  const titleM = html.match(/<h1[^>]*>([^<]+)<\/h1>/) || html.match(/<title>([^<]+)<\/title>/);
  const title = titleM ? titleM[1].replace(/\s*[-|]\s*Tokyvideo.*/i,'').trim() : 'Vídeo';
  const entry = { streamUrl: m[0], title, ts: Date.now() };
  streamCache.set(pageUrl, entry);
  return entry;
}

app.get('/api/extract', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'URL obrigatória' });

  let hostname = '';
  try { hostname = new URL(url).hostname.replace('www.',''); } catch(e) {}

  try {
    if (hostname.includes('tokyvideo.com')) {
      const info = await scrapeTokyvideo(url);
      // Retorna a URL direta pro browser testar sem proxy primeiro
      // Se o token não for vinculado ao IP, browser baixa direto do CDN
      // e o servidor fica fora da equação
      return res.json({ ok: true, url: info.streamUrl, title: info.title, referer: 'https://www.tokyvideo.com/' });
    }
    return res.json({ ok: false, error: 'Site não suportado' });
  } catch(e) {
    console.warn('[extract]', e.message);
    return res.json({ ok: false, error: e.message });
  }
});

app.get('/api/probe', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'URL obrigatória' });
  try {
    const r = await fetch(url, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0' },
      redirect: 'follow',
      signal: AbortSignal.timeout(8000)
    });
    res.json({ ok: r.ok, status: r.status, contentType: r.headers.get('content-type') || '' });
  } catch(e) {
    // HEAD não suportado — tenta GET abortado
    try {
      const ctrl = new AbortController();
      const r = await fetch(url, { method: 'GET', headers: { 'User-Agent': 'Mozilla/5.0' }, redirect: 'follow', signal: ctrl.signal });
      ctrl.abort();
      res.json({ ok: r.ok, status: r.status, contentType: r.headers.get('content-type') || '' });
    } catch(e2) {
      res.json({ ok: false, error: e2.message });
    }
  }
});

app.get('/api/stream', async (req, res) => {
  const { url, origin, h } = req.query;
  if (!url) return res.status(400).send('URL obrigatória');

  try {
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      'Accept': '*/*',
      'Accept-Encoding': 'identity',
    };
    if (origin) { headers['Referer'] = origin + '/'; headers['Origin'] = origin; }
    if (h) { try { Object.assign(headers, JSON.parse(h)); } catch(e) {} }
    if (req.headers.range) headers['Range'] = req.headers.range;

    const response = await fetch(url, { headers });
    if (!response.ok) return res.status(response.status).send('Stream error');

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', response.headers.get('content-type') || 'video/mp4');
    res.setHeader('Accept-Ranges', 'bytes');
    const cl = response.headers.get('content-length');
    const cr = response.headers.get('content-range');
    if (cl) res.setHeader('Content-Length', cl);
    if (cr) res.setHeader('Content-Range', cr);
    res.status(response.status);

    const { Readable } = require('stream');
    Readable.fromWeb(response.body).on("error", ()=>{ if(!res.headersSent) res.destroy(); }).pipe(res);
  } catch(e) {
    if (!res.headersSent) res.status(500).send('Stream proxy error: ' + e.message);
  }
});

function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'WAVE-' + Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ─────────────────────────────────────────
// SYNC HEARTBEAT — condicional por drift
// ─────────────────────────────────────────
const SYNC_DRIFT_THRESHOLD = 0.25;
const SYNC_FORCE_INTERVAL  = 5000;

setInterval(() => {
  const now = Date.now();
  rooms.forEach(room => {
    if (!room.video || room.members.size < 2) return;
    const expectedTime = getProjectedTime(room);
    room.members.forEach((member) => {
      if (member.ws.readyState !== 1) return;
      const timeSinceForce = now - (member.lastForcedSync || 0);
      if (timeSinceForce >= SYNC_FORCE_INTERVAL) {
        sendStateToMember(room, member, 'SYNC_TICK');
        member.lastForcedSync = now;
        return;
      }
      if (member.clientTime == null) { sendStateToMember(room, member, 'SYNC_TICK'); return; }
      const clientAge = (now - member.clientTimeAt) / 1000;
      const projectedClient = member.clientPlaying ? member.clientTime + clientAge : member.clientTime;
      const drift = Math.abs(projectedClient - expectedTime);
      if (drift > SYNC_DRIFT_THRESHOLD || member.clientPlaying !== room.playing) {
        sendStateToMember(room, member, 'SYNC_TICK');
      }
    });
  });
}, 500);

app.get('/api/ping', (req, res) => res.json({ ok: true }));
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ─────────────────────────────────────────
// LIKES API
// ─────────────────────────────────────────
app.post('/api/like', requireAuth, async (req, res) => {
  const { id, type } = req.body; // type: 'post' | 'photo'
  if (!id || !type) return res.status(400).json({ error: 'Parâmetros inválidos' });
  const table = type === 'photo' ? 'photo_likes' : 'post_likes';
  const col   = type === 'photo' ? 'photo_id'   : 'post_id';
  try {
    const existing = await pool.query(`SELECT id FROM ${table} WHERE user_id=$1 AND ${col}=$2`, [req.user.id, id]);
    if (existing.rows.length) {
      await pool.query(`DELETE FROM ${table} WHERE user_id=$1 AND ${col}=$2`, [req.user.id, id]);
      const { rows } = await pool.query(`SELECT COUNT(*) FROM ${table} WHERE ${col}=$1`, [id]);
      res.json({ liked: false, count: parseInt(rows[0].count) });
    } else {
      await pool.query(`INSERT INTO ${table} (user_id, ${col}) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [req.user.id, id]);
      const { rows } = await pool.query(`SELECT COUNT(*) FROM ${table} WHERE ${col}=$1`, [id]);
      res.json({ liked: true, count: parseInt(rows[0].count) });
    }
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

app.get('/api/likes/:type/:id', async (req, res) => {
  const { type, id } = req.params;
  const table = type === 'photo' ? 'photo_likes' : 'post_likes';
  const col   = type === 'photo' ? 'photo_id'   : 'post_id';
  try {
    const { rows } = await pool.query(`SELECT COUNT(*) FROM ${table} WHERE ${col}=$1`, [id]);
    const liked = req.user
      ? (await pool.query(`SELECT 1 FROM ${table} WHERE user_id=$1 AND ${col}=$2`, [req.user.id, id])).rows.length > 0
      : false;
    res.json({ count: parseInt(rows[0].count), liked });
  } catch(e) { res.json({ count: 0, liked: false }); }
});

// ─────────────────────────────────────────
// COMMENTS API
// ─────────────────────────────────────────
app.get('/api/comments/:type/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.id, c.content, c.created_at, u.name, u.username, u.avatar_url, u.avatar_emoji
       FROM post_comments c JOIN users u ON u.id = c.user_id
       WHERE c.post_id=$1 AND c.post_type=$2
       ORDER BY c.created_at ASC LIMIT 100`,
      [req.params.id, req.params.type]
    );
    res.json({ comments: rows });
  } catch(e) { res.status(500).json({ comments: [] }); }
});

app.post('/api/comments', requireAuth, async (req, res) => {
  const { post_id, post_type = 'post', content } = req.body;
  if (!post_id || !content?.trim()) return res.status(400).json({ error: 'Dados inválidos' });
  if (content.length > 500) return res.status(400).json({ error: 'Comentário muito longo' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO post_comments (user_id, post_id, post_type, content) VALUES ($1,$2,$3,$4) RETURNING id, content, created_at`,
      [req.user.id, post_id, post_type, content.trim()]
    );
    res.json({ ok: true, comment: { ...rows[0], name: req.user.name, avatar_url: req.user.avatar_url, avatar_emoji: req.user.avatar_emoji } });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM post_comments WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erro interno' }); }
});

// ─────────────────────────────────────────
// START SERVER — sempre no final, após todas as rotas
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ WaveWatch running on port ${PORT}`);
  const appUrl = process.env.RENDER_EXTERNAL_URL;
  if (appUrl) {
    // Keep-alive ping para evitar sleep no free tier
    setInterval(async () => { try { await fetch(`${appUrl}/api/ping`); } catch(e){} }, 4 * 60 * 1000);
  }
});
