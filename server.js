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
const { exec } = require('child_process');

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// DATABASE
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL não configurada');
  process.exit(1);
}

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
  `).catch(()=>{});
  console.log('✅ Database ready');
}

initDB().catch(console.error);

// SESSION + PASSPORT
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1);

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'wavewatch-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
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

// AUTH ROUTES
app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/auth/me', (req, res) => {
  if (!req.user) return res.json({ user: null });
  res.json({ user: {
    id: req.user.id,
    name: req.user.name,
    email: req.user.email
  }});
});

// EXTRACT VIDEO URL
app.get('/api/extract', (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'URL obrigatória' });
  
  // Retorna a URL direto (sem yt-dlp)
  res.json({ 
    ok: true, 
    url: url,  
    title: url.split('/').pop().split('?')[0] || 'Vídeo', 
    thumb: '' 
  });
});

// STREAM PROXY
app.get('/api/stream', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send('URL obrigatória');

  try {
    const response = await fetch(url, {
      headers: {
        'Range': req.headers.range || 'bytes=0-',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    res.set('Access-Control-Allow-Origin', '*');
    res.set('Content-Type', response.headers.get('content-type') || 'video/mp4');
    res.set('Accept-Ranges', 'bytes');
    
    if (response.headers.get('content-length')) {
      res.set('Content-Length', response.headers.get('content-length'));
    }

    const { Readable } = require('stream');
    Readable.fromWeb(response.body).pipe(res);
  } catch(e) {
    if (!res.headersSent) res.status(500).send('Erro: ' + e.message);
  }
});

// ROOM STATE
const rooms = new Map();

function getOrCreateRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      id: roomId,
      name: null,
      members: new Map(),
      video: null,
      queue: [],
      playing: false,
      currentTime: 0,
      wallClock: Date.now(),
      history: []
    });
  }
  return rooms.get(roomId);
}

function roomInfo(room) {
  return {
    id: room.id,
    members: [...room.members.values()].map(m => m.user),
    memberCount: room.members.size,
    video: room.video,
    queue: room.queue,
    playing: room.playing,
    currentTime: room.currentTime,
    history: room.history.slice(-20)
  };
}

function broadcast(room, msg, excludeId = null) {
  const data = JSON.stringify(msg);
  room.members.forEach((member, id) => {
    if (id !== excludeId && member.ws.readyState === 1) {
      member.ws.send(data);
    }
  });
}

// WEBSOCKET
wss.on('connection', (ws) => {
  const wsId = uuid();
  let currentRoom = null;
  let currentUser = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const { type, payload } = msg;

    if (type === 'JOIN') {
      currentUser = payload.user;
      currentRoom = getOrCreateRoom(payload.roomId);
      currentRoom.members.set(wsId, { ws, user: currentUser });
      const state = roomInfo(currentRoom);
      state.myWsId = wsId;
      ws.send(JSON.stringify({ type: 'ROOM_STATE', payload: state }));
      broadcast(currentRoom, { type: 'USER_JOINED', payload: { user: currentUser } }, wsId);
    }

    if (type === 'VIDEO' && currentRoom) {
      currentRoom.video = payload.video;
      currentRoom.playing = false;
      currentRoom.currentTime = 0;
      currentRoom.wallClock = Date.now();
      broadcast(currentRoom, { type: 'VIDEO', payload: { video: payload.video } });
    }

    if (type === 'QUEUE_UPDATE' && currentRoom) {
      currentRoom.queue = payload.queue;
      broadcast(currentRoom, { type: 'QUEUE_UPDATE', payload: { queue: payload.queue } });
    }

    if (type === 'CHAT' && currentRoom) {
      broadcast(currentRoom, { type: 'CHAT', payload: { user: currentUser, text: payload.text } }, wsId);
    }
  });

  ws.on('close', () => {
    if (currentRoom) {
      currentRoom.members.delete(wsId);
      if (currentRoom.members.size === 0) {
        setTimeout(() => { if (rooms.get(currentRoom.id)?.members.size === 0) rooms.delete(currentRoom.id); }, 60000);
      }
      broadcast(currentRoom, { type: 'USER_LEFT', payload: { user: currentUser } });
    }
  });
});

// REST API
app.get('/api/room/new', (req, res) => {
  const code = 'WAVE-' + Array.from({ length: 4 }, () => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[Math.floor(Math.random()*32)]).join('');
  res.json({ roomId: code });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🎬 WaveWatch rodando na porta ${PORT}`));
