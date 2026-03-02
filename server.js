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
      avatar_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_seen TIMESTAMPTZ DEFAULT NOW()
    );

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
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users (id, name, email, password_hash) VALUES ($1,$2,$3,$4) RETURNING *',
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
    email: req.user.email,
    avatarUrl: req.user.avatar_url,
    googleAccessToken: req.session.googleAccessToken || null
  }});
});

// ── GOOGLE DRIVE PROXY STREAM ──
app.get('/api/config', (req, res) => {
  res.json({ googleApiKey: process.env.GOOGLE_API_KEY || '' });
});

// ── PROXY REVERSO PARA IFRAME (remove X-Frame-Options) ──
const BLOCKED_HEADERS = new Set([
  'x-frame-options','content-security-policy','x-content-type-options',
  'strict-transport-security','permissions-policy','cross-origin-opener-policy',
  'cross-origin-embedder-policy','cross-origin-resource-policy'
]);

function buildProxyBase(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}/api/proxy?url=`;
}

function rewriteUrl(rawUrl, targetOrigin, targetHref, proxyBase) {
  if (!rawUrl || rawUrl.startsWith('data:') || rawUrl.startsWith('blob:') || rawUrl.startsWith('javascript:') || rawUrl.startsWith('#')) return rawUrl;
  try {
    const abs = new URL(rawUrl, targetHref).href;
    return proxyBase + encodeURIComponent(abs);
  } catch { return rawUrl; }
}

function rewriteHtml(html, target, proxyBase) {
  const origin = target.origin;
  const href = target.href;

  // Rewrite src/href/action attributes (single and double quotes)
  html = html.replace(/(\b(?:src|href|action|data-src|data-href)\s*=\s*)(['"])(.*?)\2/gi, (match, attr, quote, url) => {
    return attr + quote + rewriteUrl(url, origin, href, proxyBase) + quote;
  });

  // Rewrite srcset attributes
  html = html.replace(/(\bsrcset\s*=\s*)(['"])(.*?)\2/gi, (match, attr, quote, srcset) => {
    const rewritten = srcset.replace(/([^\s,]+)(\s*(?:\s+\d+[wx])?)/g, (m, url, desc) => {
      return rewriteUrl(url.trim(), origin, href, proxyBase) + desc;
    });
    return attr + quote + rewritten + quote;
  });

  // Rewrite CSS url() in style attributes and <style> blocks
  html = html.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, url) => {
    return `url(${quote}${rewriteUrl(url, origin, href, proxyBase)}${quote})`;
  });

  // Rewrite window.location / fetch / XHR URLs em scripts inline (heurística)
  // Substitui strings absolutas que apontam para o domínio alvo
  html = html.replace(new RegExp(`(['"])${origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^'"]*?)\\1`, 'g'), (match, quote, path) => {
    return quote + proxyBase + encodeURIComponent(origin + path) + quote;
  });

  return html;
}

function rewriteCss(css, target, proxyBase) {
  return css.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, url) => {
    return `url(${quote}${rewriteUrl(url, target.origin, target.href, proxyBase)}${quote})`;
  });
}

app.get('/api/proxy', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send('URL required');

  let target;
  try { target = new URL(url); } catch { return res.status(400).send('URL inválida'); }

  const proxyBase = buildProxyBase(req);

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'identity',
        'Referer': target.origin + '/',
        'Origin': target.origin,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Upgrade-Insecure-Requests': '1'
      },
      redirect: 'follow'
    });

    // Filtra headers problemáticos
    response.headers.forEach((val, key) => {
      const lower = key.toLowerCase();
      if (!BLOCKED_HEADERS.has(lower) && lower !== 'set-cookie' && lower !== 'transfer-encoding') {
        try { res.setHeader(key, val); } catch {}
      }
    });

    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('text/html')) {
      let html = await response.text();
      html = rewriteHtml(html, target, proxyBase);

      // Injeta script de controle do player + intercepta fetch/XHR
      const controlScript = `
<script>
(function() {
  const PROXY = ${JSON.stringify(proxyBase)};
  const ORIGIN = ${JSON.stringify(target.origin)};

  // Intercepta fetch para reescrever URLs relativas/absolutas do site alvo
  const _fetch = window.fetch;
  window.fetch = function(input, init) {
    try {
      let u = typeof input === 'string' ? input : (input.url || input);
      if (typeof u === 'string' && !u.startsWith('blob:') && !u.startsWith('data:')) {
        const abs = new URL(u, ORIGIN).href;
        if (abs.startsWith(ORIGIN)) u = PROXY + encodeURIComponent(abs);
        input = typeof input === 'string' ? u : new Request(u, input);
      }
    } catch {}
    return _fetch.apply(this, [input, init]);
  };

  // Intercepta XMLHttpRequest
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      const abs = new URL(url, ORIGIN).href;
      if (abs.startsWith(ORIGIN)) url = PROXY + encodeURIComponent(abs);
    } catch {}
    return _open.call(this, method, url, ...rest);
  };

  // Encontra o elemento <video> — espera até 30s
  function findVideo(cb, attempts) {
    attempts = attempts || 0;
    const v = document.querySelector('video:not([data-ww])');
    if (v) { v.dataset.ww = '1'; cb(v); return; }
    // Também procura em shadow roots
    const all = document.querySelectorAll('*');
    for (const el of all) {
      if (el.shadowRoot) {
        const sv = el.shadowRoot.querySelector('video:not([data-ww])');
        if (sv) { sv.dataset.ww = '1'; cb(sv); return; }
      }
    }
    if (attempts < 60) setTimeout(() => findVideo(cb, attempts + 1), 500);
  }

  // Escuta comandos do WaveWatch (play/pause/seek)
  window.addEventListener('message', function(e) {
    if (!e.data || !e.data.type) return;
    findVideo(function(v) {
      if (e.data.type === 'WW_PLAY') { v.play().catch(()=>{}); }
      if (e.data.type === 'WW_PAUSE') { v.pause(); }
      if (e.data.type === 'WW_SEEK') { v.currentTime = e.data.time; }
    });
  });

  // Observa inserção de elementos video no DOM dinamicamente — inclui múltiplos videos (anúncio + principal)
  const observer = new MutationObserver(() => {
    document.querySelectorAll('video').forEach(v => attachVideo(v));
    document.querySelectorAll('*').forEach(el => {
      if (el.shadowRoot) el.shadowRoot.querySelectorAll('video').forEach(v => attachVideo(v));
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // Rastreia todos os videos — anuncios e video principal
  const videoSet = new Set();

  function attachVideo(v) {
    if (videoSet.has(v)) return;
    videoSet.add(v);

    // Detecta se é anúncio (curto, ou tem atributo de ad)
    function isAd(vid) {
      return (vid.duration > 0 && vid.duration < 120) ||
             vid.closest && (vid.closest('[class*="ad"]') || vid.closest('[id*="ad"]') || vid.closest('[class*="vast"]'));
    }

    v.addEventListener('play', () => {
      if (isAd(v)) return; // ignora anúncios
      window.parent.postMessage({type:'WW_PLAYING', time: v.currentTime}, '*');
    });
    v.addEventListener('pause', () => {
      if (isAd(v)) return;
      window.parent.postMessage({type:'WW_PAUSED', time: v.currentTime}, '*');
    });
    v.addEventListener('seeked', () => {
      if (isAd(v)) return;
      window.parent.postMessage({type:'WW_SEEKED', time: v.currentTime}, '*');
    });
    v.addEventListener('timeupdate', () => {
      if (isAd(v)) return;
      if (Math.floor(v.currentTime) % 2 === 0)
        window.parent.postMessage({type:'WW_TIME', time: v.currentTime, duration: v.duration||0}, '*');
    });

    // Quando anúncio termina, notifica que está pronto
    v.addEventListener('ended', () => {
      if (isAd(v)) {
        // Anúncio acabou — avisa WaveWatch pra se preparar
        window.parent.postMessage({type:'WW_AD_ENDED'}, '*');
        // Procura novo video que pode aparecer
        setTimeout(() => findVideo(attachVideo, 0), 500);
      }
    });

    if (!isAd(v)) {
      window.parent.postMessage({type:'WW_READY'}, '*');
    }
  }

  // Tenta logo e via observer
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => findVideo(attachVideo));
  else findVideo(attachVideo);
})();
</script>`;

      // Injeta no <head> para rodar antes de scripts do site
      if (html.includes('<head>')) {
        html = html.replace('<head>', '<head>' + controlScript);
      } else if (html.includes('<body')) {
        html = html.replace('<body', controlScript + '<body');
      } else {
        html = controlScript + html;
      }

      res.removeHeader('x-frame-options');
      res.removeHeader('content-security-policy');
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.send(html);

    } else if (contentType.includes('text/css')) {
      let css = await response.text();
      css = rewriteCss(css, target, proxyBase);
      res.removeHeader('content-security-policy');
      res.setHeader('content-type', 'text/css; charset=utf-8');
      res.send(css);

    } else if (contentType.includes('application/vnd.apple.mpegurl') || contentType.includes('application/x-mpegurl') || url.includes('.m3u8')) {
      // Reescreve playlists HLS (.m3u8) para que os segmentos passem pelo proxy
      let m3u8 = await response.text();
      m3u8 = m3u8.split('\n').map(line => {
        line = line.trim();
        if (!line || line.startsWith('#')) return line;
        // Reescreve URLs de segmentos e sub-playlists
        return proxyBase + encodeURIComponent(rewriteUrl(line, target.origin, target.href, proxyBase).replace(proxyBase, '').split('?')[0] ? new URL(line, target.href).href : line);
      }).join('\n');
      res.removeHeader('content-security-policy');
      res.setHeader('content-type', 'application/vnd.apple.mpegurl');
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.send(m3u8);

    } else {
      // Recursos binários (JS, imagens, vídeo, fontes, segmentos HLS .ts) — proxy direto com streaming
      res.removeHeader('content-security-policy');
      res.removeHeader('x-frame-options');
      res.setHeader('Access-Control-Allow-Origin', '*');
      const { Readable } = require('stream');
      Readable.fromWeb(response.body).pipe(res);
    }

  } catch(e) {
    console.error('Proxy error:', e.message);
    res.status(500).send(`
      <html><body style="background:#08090f;color:#f0f0ff;font-family:sans-serif;padding:2rem;text-align:center">
        <h2>⚠️ Proxy não conseguiu carregar este site</h2>
        <p style="color:#8b8ea8">Erro: ${e.message}</p>
        <p style="color:#8b8ea8;font-size:.85rem">Alguns sites bloqueiam ativamente proxies. Tente copiar a URL direta do vídeo (MP4/M3U8).</p>
      </body></html>
    `);
  }
});

app.get('/api/drive/stream/:fileId', async (req, res) => {
  const { fileId } = req.params;
  const token = req.session.googleAccessToken;

  try {
    let driveRes;

    if (token) {
      // Authenticated request via Drive API — works for owner's files
      const driveUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`;
      const fetchHeaders = { 'Authorization': `Bearer ${token}` };
      if (req.headers.range) fetchHeaders['Range'] = req.headers.range;
      driveRes = await fetch(driveUrl, { headers: fetchHeaders });
    } else {
      // Public file fallback
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
    driveRes.body.pipe(res);
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

// Search users by name
app.get('/api/users/search', requireAuth, async (req, res) => {
  const q = req.query.q?.trim();
  if (!q) return res.json({ users: [] });
  try {
    const { rows } = await pool.query(`
      SELECT id, name, avatar_url FROM users
      WHERE name ILIKE $1 AND id != $2
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

// List friends (accepted)
app.get('/api/friends', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.name, u.avatar_url, f.status
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
      SELECT u.id, u.name, u.avatar_url
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
      const { roomId, user, roomName, isPublic, category } = payload;
      currentUser = { ...user, id: wsId, joinedAt: Date.now() };
      currentRoom = getOrCreateRoom(roomId);
      if (currentRoom.members.size === 0) {
        currentRoom.host = wsId;
        currentRoom.hostName = user.name;
        currentUser.isHost = true;
        // Set room metadata on creation
        if (roomName) currentRoom.name = roomName;
        if (isPublic !== undefined) currentRoom.isPublic = !!isPublic;
        if (category) currentRoom.category = category;
      }
      currentRoom.members.set(wsId, { ws, user: currentUser, rtt: 80 });
      ws.send(JSON.stringify({ type: 'ROOM_STATE', payload: roomInfo(currentRoom) }));
      broadcast(currentRoom, { type: 'USER_JOINED', payload: { user: currentUser, memberCount: currentRoom.members.size } }, wsId);
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

    // ── BOOKMARKLET SYNC ──
    if (type === 'BM_JOIN') {
      const { roomId, userId, url } = payload;
      currentRoom = getOrCreateRoom(roomId);
      currentUser = { id: wsId, name: 'Sync:' + userId, isBookmarklet: true };
      currentRoom.members.set(wsId, { ws, user: currentUser, rtt: 80 });
      broadcastAll(currentRoom, { type: 'BM_MEMBERS', payload: { count: currentRoom.members.size } });
      ws.send(JSON.stringify({ type: 'BM_MEMBERS', payload: { count: currentRoom.members.size } }));
    }

    if (type === 'BM_PLAY' && currentRoom) {
      broadcast(currentRoom, { type: 'BM_PLAY', payload }, wsId);
      currentRoom.playing = true;
      currentRoom.currentTime = payload.time || 0;
      currentRoom.wallClock = Date.now();
    }

    if (type === 'BM_PAUSE' && currentRoom) {
      broadcast(currentRoom, { type: 'BM_PAUSE', payload }, wsId);
      currentRoom.playing = false;
      currentRoom.currentTime = payload.time || 0;
      currentRoom.wallClock = Date.now();
    }

    if (type === 'BM_SEEK' && currentRoom) {
      broadcast(currentRoom, { type: 'BM_SEEK', payload }, wsId);
      currentRoom.currentTime = payload.time || 0;
      currentRoom.wallClock = Date.now();
    }

    if (type === 'CHAT' && currentRoom) {
      broadcastAll(currentRoom, { type: 'CHAT', payload: { id: uuid(), user: currentUser, text: payload.text, ts: Date.now() } });
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

// ── BOOKMARKLET: serve o código já com o host correto ──
app.get('/api/bm/code', (req, res) => {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.get('host');
  const wsProto = proto === 'https' ? 'wss' : 'ws';

  const code = `(function(){if(window.__ww_sync){window.__ww_sync.toggle();return;}const WW_HOST="${host}";const WS_URL="${wsProto}://${host}";const bar=document.createElement('div');bar.id='__ww_bar';bar.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;height:40px;background:linear-gradient(135deg,#e84393,#7c5cfc);display:flex;align-items:center;padding:0 16px;gap:12px;font-family:system-ui,sans-serif;font-size:13px;color:#fff;box-shadow:0 2px 16px rgba(0,0,0,.4);transition:transform .3s ease';bar.innerHTML='<span style="font-weight:700;letter-spacing:-.3px">🌊 WaveWatch</span><span id="__ww_status" style="font-size:11px;opacity:.85;font-family:monospace">Conectando...</span><span id="__ww_room" style="font-size:11px;background:rgba(255,255,255,.2);padding:2px 8px;border-radius:20px;font-family:monospace"></span><span id="__ww_users" style="font-size:11px;opacity:.75"></span><span style="margin-left:auto;display:flex;gap:8px;align-items:center"><span id="__ww_dot" style="width:8px;height:8px;border-radius:50%;background:#fff;opacity:.4"></span><button id="__ww_close" style="background:rgba(255,255,255,.2);border:none;color:#fff;width:24px;height:24px;border-radius:50%;cursor:pointer;font-size:14px;line-height:1">✕</button></span>';document.body.appendChild(bar);document.body.style.marginTop='40px';function ss(t,ok){document.getElementById('__ww_status').textContent=t;var d=document.getElementById('__ww_dot');d.style.background=ok?'#00d4aa':'#fff';d.style.opacity=ok?1:.4;if(ok)d.style.boxShadow='0 0 6px #00d4aa';else d.style.boxShadow='';}document.getElementById('__ww_close').onclick=function(){bar.style.transform='translateY(-100%)';document.body.style.marginTop='';setTimeout(function(){bar.remove();window.__ww_sync=null;},300);if(ws)ws.close();};var ws=null,roomId=null,video=null,syncing=false,myId='bm_'+Math.random().toString(36).slice(2,8);fetch('https://'+WW_HOST+'/api/bm/session',{credentials:'include'}).then(function(r){return r.json();}).then(function(d){if(!d.roomId){ss('Nenhuma sala ativa — entre no WaveWatch primeiro',false);return;}roomId=d.roomId;document.getElementById('__ww_room').textContent=roomId;connect();}).catch(function(){ss('Erro ao conectar',false);});function connect(){ws=new WebSocket(WS_URL);ws.onopen=function(){ss('Sincronizando',true);ws.send(JSON.stringify({type:'BM_JOIN',payload:{roomId:roomId,userId:myId,url:location.href}}));attachVideo();};ws.onmessage=function(e){var m=JSON.parse(e.data);if(m.type==='BM_MEMBERS')document.getElementById('__ww_users').textContent='👥 '+m.payload.count;if(m.type==='BM_PLAY')apply('play',m.payload.time);if(m.type==='BM_PAUSE')apply('pause',m.payload.time);if(m.type==='BM_SEEK')apply('seek',m.payload.time);};ws.onclose=function(){ss('Desconectado',false);};ws.onerror=function(){ss('Erro',false);};}function fv(){var v=document.querySelector('video');if(v)return v;for(var el of document.querySelectorAll('*')){if(el.shadowRoot){var sv=el.shadowRoot.querySelector('video');if(sv)return sv;}}return null;}function attachVideo(){video=fv();if(!video){ss('Aguardando player...',true);var obs=new MutationObserver(function(){var v=fv();if(v){obs.disconnect();video=v;hook();}});obs.observe(document.documentElement,{childList:true,subtree:true});return;}hook();}function hook(){ss('Sincronizando',true);video.addEventListener('play',function(){if(syncing)return;send('BM_PLAY',{time:video.currentTime});});video.addEventListener('pause',function(){if(syncing)return;send('BM_PAUSE',{time:video.currentTime});});video.addEventListener('seeked',function(){if(syncing)return;send('BM_SEEK',{time:video.currentTime});});}function apply(a,t){if(!video){video=fv();if(!video)return;}syncing=true;if(Math.abs(video.currentTime-t)>1)video.currentTime=t;if(a==='play')video.play().catch(function(){});if(a==='pause')video.pause();setTimeout(function(){syncing=false;},300);}function send(type,payload){if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:type,payload:Object.assign({},payload,{roomId:roomId})}));}window.__ww_sync={toggle:function(){var h=bar.style.transform==='translateY(-100%)';bar.style.transform=h?'':'translateY(-100%)';document.body.style.marginTop=h?'40px':'';}}; })();`;

  res.setHeader('Content-Type', 'application/javascript');
  res.send(`javascript:${encodeURIComponent(code)}`);
});

// ── BOOKMARKLET: salva sala ativa do usuário ──
app.post('/api/bm/session', requireAuth, (req, res) => {
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: 'roomId required' });
  req.session.bmRoom = roomId;
  req.session.save();
  res.json({ ok: true });
});

// ── BOOKMARKLET: retorna sala ativa + host do WS ──
app.get('/api/bm/session', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  const roomId = req.session?.bmRoom || null;
  const wsHost = req.get('host');
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const wsUrl = (proto === 'https' ? 'wss' : 'ws') + '://' + wsHost;
  res.json({ roomId, wsUrl, host: wsHost });
});

// ── EXTRATOR DE URL DIRETA DE VÍDEO ──────────────────────────
// Lê o HTML público da página e extrai a URL do vídeo.
// O vídeo vai direto do CDN pro usuário — nunca passa pelo servidor.
app.get('/api/extract', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'URL required' });

  try {
    const target = new URL(url);
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'Referer': target.origin
      }
    });

    const html = await response.text();

    const found = new Set();

    // 1. MP4/WebM URLs diretas
    const directPattern = /https?:\/\/[^\s"'<>]+\.(?:mp4|webm|ogv|ogg)(?:\?[^\s"'<>]*)?/gi;
    let m;
    while ((m = directPattern.exec(html)) !== null) {
      found.add(m[0]);
    }

    // 2. M3U8 (HLS)
    const hlsPattern = /https?:\/\/[^\s"'<>]+\.m3u8(?:\?[^\s"'<>]*)?/gi;
    while ((m = hlsPattern.exec(html)) !== null) {
      found.add(m[0]);
    }

    // 3. JSON fields comuns de players
    const jsonPattern = /"(?:src|url|file|videoUrl|mp4|stream|source|hls|video_url)"\s*:\s*"(https?:[^"]+)"/gi;
    while ((m = jsonPattern.exec(html)) !== null) {
      found.add(m[1]);
    }

    // 4. Atributos HTML
    const attrPattern = /(?:src|href|data-src|data-url)\s*=\s*['"]([^'"]+\.(?:mp4|webm|m3u8|ogv)[^'"]*)['"]/gi;
    while ((m = attrPattern.exec(html)) !== null) {
      found.add(m[1]);
    }

    // Filtra lixo
    const blocked = ['googlesyndication','doubleclick','ads.','/ad/','adserver','googleads'];
    const urls = [...found].filter(u => {
      if (u.length < 15) return false;
      if (u.includes('undefined')) return false;
      if (blocked.some(b => u.includes(b))) return false;
      return true;
    });

    // Ordena: mp4 primeiro, depois m3u8
    urls.sort((a, b) => {
      const score = u => u.includes('.mp4') ? 2 : u.includes('.m3u8') ? 1 : 0;
      return score(b) - score(a);
    });

    if (!urls.length) {
      return res.json({ error: 'Nenhum vídeo encontrado. O site pode proteger as URLs.', urls: [] });
    }

    // Tenta buscar título da página
    const titleMatch = html.match(/<title>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].replace(/\s*[-|].*$/, '').trim() : url.split('/').pop();

    // Tenta buscar thumbnail
    const thumbMatch = html.match(/(?:og:image|twitter:image)[^>]*content="([^"]+)"/i) ||
                       html.match(/content="([^"]+)"[^>]*(?:og:image|twitter:image)/i);
    const thumb = thumbMatch ? thumbMatch[1] : '';

    res.json({ urls, title, thumb, total: urls.length });

  } catch(e) {
    res.status(500).json({ error: 'Erro ao analisar a página: ' + e.message });
  }
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
