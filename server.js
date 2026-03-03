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
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
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

    CREATE INDEX IF NOT EXISTS IDX_session_expire ON session (expire);
  `);
  console.log('✅ Database ready');
}

initDB().catch(console.error);

// ─────────────────────────────────────────
// SESSION + PASSPORT
// ─────────────────────────────────────────
app.use(express.json());
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

// ─────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email', 'https://www.googleapis.com/auth/drive.readonly'] })
);

// Re-auth just to get Drive token (user already logged in)
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
    // Token is stored on req.user._googleAccessToken during strategy
    // Save it to session so it persists
    if (req.user._googleAccessToken) {
      req.session.googleAccessToken = req.user._googleAccessToken;
    }
    res.redirect('/');
  }
);

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
    profileComplete: req.user.profile_complete || false,
    googleAccessToken: req.session.googleAccessToken || null
  }});
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
  const { username, avatarEmoji, displayName } = req.body;

  // If user already has a username and none was sent, keep the existing one
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
    const { rows } = await pool.query(
      'UPDATE users SET username=$1, avatar_emoji=$2, name=$3, profile_complete=TRUE WHERE id=$4 RETURNING *',
      [finalUsername, emoji, safeName, req.user.id]
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
      Readable.fromWeb(response.body).pipe(res);
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
    Readable.fromWeb(driveRes.body).pipe(res);
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
        member.rtt = member.rtt ? Math.round(member.rtt * 0.7 + measured * 0.3) : measured;
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
      if (payload.video && !currentRoom.history.find(h => h.url === payload.video.url)) {
        currentRoom.history.unshift({ ...payload.video, addedAt: Date.now(), addedBy: currentUser.name });
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

app.get('/api/yt/search', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json({ items: [] });
  try {
    const url = `https://suggestqueries.google.com/complete/search?client=youtube&ds=yt&q=${encodeURIComponent(q)}&callback=f`;
    const r = await fetch(url);
    const text = await r.text();
    const json = JSON.parse(text.slice(2, -1));
    res.json({ suggestions: (json[1] || []).slice(0, 8).map(s => s[0]) });
  } catch (e) { res.json({ suggestions: [] }); }
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

function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'WAVE-' + Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ─────────────────────────────────────────
// SYNC HEARTBEAT
// ─────────────────────────────────────────
setInterval(() => {
  rooms.forEach(room => {
    if (!room.video || room.members.size < 2) return;
    room.members.forEach(member => sendStateToMember(room, member, 'SYNC_TICK'));
  });
}, 1500);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`WaveWatch running on port ${PORT}`));
