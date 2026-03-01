const express = require('express');
const { WebSocketServer } = require('ws');
const { createServer } = require('http');
const { v4: uuid } = require('uuid');
const path = require('path');

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────
// ROOM STATE
// ─────────────────────────────────────────
const rooms = new Map();
// room = {
//   id, host, members: Map<wsId, {ws, user}>,
//   video: {src, url, title, thumb},
//   queue: [], playing: false, currentTime: 0,
//   lastUpdate: timestamp, history: []
// }

function getOrCreateRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      id: roomId,
      host: null,
      members: new Map(),
      video: null,
      queue: [],
      playing: false,
      currentTime: 0,
      lastUpdate: Date.now(),
      history: []
    });
  }
  return rooms.get(roomId);
}

function roomInfo(room) {
  return {
    id: room.id,
    host: room.host,
    members: [...room.members.values()].map(m => m.user),
    memberCount: room.members.size,
    video: room.video,
    queue: room.queue,
    playing: room.playing,
    currentTime: room.currentTime,
    lastUpdate: room.lastUpdate,
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

function broadcastAll(room, msg) {
  broadcast(room, msg, null);
}

// ─────────────────────────────────────────
// WEBSOCKET HANDLER
// ─────────────────────────────────────────
wss.on('connection', (ws) => {
  const wsId = uuid();
  let currentRoom = null;
  let currentUser = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const { type, payload } = msg;

    // JOIN
    if (type === 'JOIN') {
      const { roomId, user } = payload;
      currentUser = { ...user, id: wsId, joinedAt: Date.now() };
      currentRoom = getOrCreateRoom(roomId);

      // Set host if first member
      if (currentRoom.members.size === 0) {
        currentRoom.host = wsId;
        currentUser.isHost = true;
      }

      currentRoom.members.set(wsId, { ws, user: currentUser });

      // Send current room state to the new member
      ws.send(JSON.stringify({
        type: 'ROOM_STATE',
        payload: roomInfo(currentRoom)
      }));

      // Notify others
      broadcast(currentRoom, {
        type: 'USER_JOINED',
        payload: { user: currentUser, memberCount: currentRoom.members.size }
      }, wsId);
    }

    // PING — measure latency
    if (type === 'PING') {
      ws.send(JSON.stringify({ type: 'PONG', payload: { ts: payload.ts } }));
      // Store RTT estimate for this member (will be updated by client)
      const member = currentRoom?.members.get(wsId);
      if (member) member.rtt = Date.now() - payload.ts;
    }

    // CHAT
    if (type === 'CHAT' && currentRoom) {
      const chatMsg = {
        id: uuid(),
        user: currentUser,
        text: payload.text,
        ts: Date.now()
      };
      broadcastAll(currentRoom, { type: 'CHAT', payload: chatMsg });
    }

    // REACTION
    if (type === 'REACTION' && currentRoom) {
      broadcastAll(currentRoom, {
        type: 'REACTION',
        payload: { emoji: payload.emoji, user: currentUser, ts: Date.now() }
      });
    }

    // VIDEO — set current video
    if (type === 'VIDEO' && currentRoom) {
      currentRoom.video = payload.video;
      currentRoom.playing = false;
      currentRoom.currentTime = 0;
      currentRoom.lastUpdate = Date.now();
      // Add to history
      if (payload.video && !currentRoom.history.find(h => h.url === payload.video.url)) {
        currentRoom.history.unshift({ ...payload.video, addedAt: Date.now(), addedBy: currentUser.name });
        if (currentRoom.history.length > 50) currentRoom.history.pop();
      }
      broadcastAll(currentRoom, { type: 'VIDEO', payload: { video: payload.video, by: currentUser } });
    }

    // QUEUE
    if (type === 'QUEUE_UPDATE' && currentRoom) {
      currentRoom.queue = payload.queue;
      broadcastAll(currentRoom, { type: 'QUEUE_UPDATE', payload: { queue: currentRoom.queue, by: currentUser } });
    }

    // PLAY/PAUSE
    if (type === 'STATE' && currentRoom) {
      currentRoom.playing = payload.playing;
      currentRoom.currentTime = payload.currentTime;
      currentRoom.lastUpdate = Date.now();
      broadcast(currentRoom, {
        type: 'STATE',
        payload: { playing: payload.playing, currentTime: payload.currentTime }
      }, wsId);
    }

    // SEEK
    if (type === 'SEEK' && currentRoom) {
      currentRoom.currentTime = payload.t;
      currentRoom.lastUpdate = Date.now();
      broadcast(currentRoom, { type: 'SEEK', payload: { t: payload.t } }, wsId);
    }
  });

  ws.on('close', () => {
    if (!currentRoom) return;
    currentRoom.members.delete(wsId);
    // Transfer host if needed
    if (currentRoom.host === wsId && currentRoom.members.size > 0) {
      const newHostId = currentRoom.members.keys().next().value;
      currentRoom.host = newHostId;
      const newHostMember = currentRoom.members.get(newHostId);
      if (newHostMember) {
        newHostMember.user.isHost = true;
        broadcastAll(currentRoom, { type: 'HOST_CHANGED', payload: { hostId: newHostId } });
      }
    }
    // Clean up empty rooms after delay
    if (currentRoom.members.size === 0) {
      setTimeout(() => {
        if (rooms.get(currentRoom.id)?.members.size === 0) {
          rooms.delete(currentRoom.id);
        }
      }, 60000);
    }
    broadcast(currentRoom, {
      type: 'USER_LEFT',
      payload: { user: currentUser, memberCount: currentRoom.members.size }
    });
  });
});

// ─────────────────────────────────────────
// REST API
// ─────────────────────────────────────────

// Generate room ID
app.get('/api/room/new', (req, res) => {
  const id = generateRoomCode();
  res.json({ roomId: id });
});

// Room exists check
app.get('/api/room/:id', (req, res) => {
  const room = rooms.get(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  res.json({ exists: true, memberCount: room.members.size });
});

// YouTube search proxy (uses YouTube oEmbed + search suggestion)
app.get('/api/yt/search', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json({ items: [] });
  try {
    // Use YouTube search suggestions API (no API key needed)
    const url = `https://suggestqueries.google.com/complete/search?client=youtube&ds=yt&q=${encodeURIComponent(q)}&callback=f`;
    const r = await fetch(url);
    const text = await r.text();
    const json = JSON.parse(text.slice(2, -1));
    const suggestions = (json[1] || []).slice(0, 8).map(s => s[0]);
    res.json({ suggestions });
  } catch (e) {
    res.json({ suggestions: [] });
  }
});

// YouTube oEmbed to get video info
app.get('/api/yt/info', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'No URL' });
  try {
    const oembed = `https://www.youtube.com/oembed?url=${encodeURIComponent(url)}&format=json`;
    const r = await fetch(oembed);
    if (!r.ok) throw new Error('Not found');
    const data = await r.json();
    res.json({
      title: data.title,
      thumb: data.thumbnail_url,
      author: data.author_name
    });
  } catch (e) {
    res.status(404).json({ error: 'Video not found or unavailable' });
  }
});

function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'WAVE-' + Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ─────────────────────────────────────────
// PERIODIC SYNC PING — every 5s, host state is pushed to all guests
// ─────────────────────────────────────────
setInterval(() => {
  rooms.forEach(room => {
    if (room.members.size < 2 || !room.video) return;
    // Send clean projected time to all non-host members
    const elapsed = (Date.now() - room.lastUpdate) / 1000;
    const projected = room.currentTime + (room.playing ? elapsed : 0);
    const data = JSON.stringify({
      type: 'SYNC_PING',
      payload: { playing: room.playing, currentTime: projected }
    });
    room.members.forEach((member, id) => {
      if (id !== room.host && member.ws.readyState === 1) {
        member.ws.send(data);
      }
    });
  });
}, 2000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`WaveWatch running on port ${PORT}`));
