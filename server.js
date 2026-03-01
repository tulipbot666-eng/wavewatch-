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

function getOrCreateRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      id: roomId,
      host: null,
      members: new Map(),
      video: null,
      queue: [],
      playing: false,
      currentTime: 0,        // video time at moment of last state change
      wallClock: Date.now(), // real-world timestamp of last state change — THE master clock
      history: []
    });
  }
  return rooms.get(roomId);
}

// Core of Rave-style sync:
// We store (currentTime, wallClock) and calculate projected position on demand.
// This means the server always knows where the video "is" right now.
function getProjectedTime(room) {
  if (!room.playing) return room.currentTime;
  const elapsed = (Date.now() - room.wallClock) / 1000;
  return room.currentTime + elapsed;
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
    currentTime: getProjectedTime(room), // always the live projected time
    wallClock: room.wallClock,
    serverNow: Date.now(),
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

// Send a sync message to a specific member with their individual RTT compensation.
// By the time the message arrives, rtt/2 ms will have passed,
// so we pre-compensate so the client lands on the right frame.
function sendStateToMember(room, member, msgType) {
  if (member.ws.readyState !== 1) return;
  const rtt = member.rtt || 80;
  const projected = getProjectedTime(room);
  const compensated = projected + (room.playing ? (rtt / 2000) : 0);
  member.ws.send(JSON.stringify({
    type: msgType || 'SYNC_TICK',
    payload: {
      playing: room.playing,
      currentTime: compensated,
      wallClock: room.wallClock,
      serverNow: Date.now()
    }
  }));
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

    // ── JOIN ──────────────────────────────────────────────
    if (type === 'JOIN') {
      const { roomId, user } = payload;
      currentUser = { ...user, id: wsId, joinedAt: Date.now() };
      currentRoom = getOrCreateRoom(roomId);

      if (currentRoom.members.size === 0) {
        currentRoom.host = wsId;
        currentUser.isHost = true;
      }

      currentRoom.members.set(wsId, { ws, user: currentUser, rtt: 80 });

      // Send full room state with live projected time to the new member
      ws.send(JSON.stringify({
        type: 'ROOM_STATE',
        payload: roomInfo(currentRoom)
      }));

      broadcast(currentRoom, {
        type: 'USER_JOINED',
        payload: { user: currentUser, memberCount: currentRoom.members.size }
      }, wsId);
    }

    // ── PING — measure per-client RTT with exponential moving average ──
    if (type === 'PING') {
      const now = Date.now();
      ws.send(JSON.stringify({
        type: 'PONG',
        payload: { ts: payload.ts, serverNow: now }
      }));
      const member = currentRoom?.members.get(wsId);
      if (member) {
        const measured = now - payload.ts;
        // EMA smoothing: reduces impact of network spikes
        member.rtt = member.rtt
          ? Math.round(member.rtt * 0.7 + measured * 0.3)
          : measured;
      }
    }

    // ── CHAT ──────────────────────────────────────────────
    if (type === 'CHAT' && currentRoom) {
      broadcastAll(currentRoom, {
        type: 'CHAT',
        payload: { id: uuid(), user: currentUser, text: payload.text, ts: Date.now() }
      });
    }

    // ── REACTION ──────────────────────────────────────────
    if (type === 'REACTION' && currentRoom) {
      broadcastAll(currentRoom, {
        type: 'REACTION',
        payload: { emoji: payload.emoji, user: currentUser, ts: Date.now() }
      });
    }

    // ── VIDEO — new video set ──────────────────────────────
    if (type === 'VIDEO' && currentRoom) {
      currentRoom.video = payload.video;
      currentRoom.playing = false;
      currentRoom.currentTime = 0;
      currentRoom.wallClock = Date.now();
      if (payload.video && !currentRoom.history.find(h => h.url === payload.video.url)) {
        currentRoom.history.unshift({ ...payload.video, addedAt: Date.now(), addedBy: currentUser.name });
        if (currentRoom.history.length > 50) currentRoom.history.pop();
      }
      broadcastAll(currentRoom, {
        type: 'VIDEO',
        payload: { video: payload.video, by: currentUser }
      });
    }

    // ── QUEUE ──────────────────────────────────────────────
    if (type === 'QUEUE_UPDATE' && currentRoom) {
      currentRoom.queue = payload.queue;
      broadcastAll(currentRoom, {
        type: 'QUEUE_UPDATE',
        payload: { queue: currentRoom.queue, by: currentUser }
      });
    }

    // ── PLAY / PAUSE ───────────────────────────────────────
    // Host sends currentTime. We correct for host's own RTT (the event happened
    // rtt/2 ms ago), then broadcast to each guest with their individual RTT offset.
    if (type === 'STATE' && currentRoom) {
      const hostMember = currentRoom.members.get(wsId);
      const hostRtt = hostMember?.rtt || 80;

      // The host sent this message rtt/2 ms ago, so the true "now" is slightly ahead
      const trueTime = payload.currentTime + (payload.playing ? hostRtt / 2000 : 0);

      currentRoom.playing = payload.playing;
      currentRoom.currentTime = trueTime;
      currentRoom.wallClock = Date.now();

      // Broadcast to each guest individually with their RTT compensation
      currentRoom.members.forEach((member, id) => {
        if (id === wsId || member.ws.readyState !== 1) return;
        sendStateToMember(currentRoom, member, 'STATE');
      });
    }

    // ── SEEK ───────────────────────────────────────────────
    if (type === 'SEEK' && currentRoom) {
      const hostMember = currentRoom.members.get(wsId);
      const hostRtt = hostMember?.rtt || 80;
      const trueTime = payload.t + (currentRoom.playing ? hostRtt / 2000 : 0);

      currentRoom.currentTime = trueTime;
      currentRoom.wallClock = Date.now();

      currentRoom.members.forEach((member, id) => {
        if (id === wsId || member.ws.readyState !== 1) return;
        const guestRtt = member.rtt || 80;
        const compensated = trueTime + (currentRoom.playing ? guestRtt / 2000 : 0);
        member.ws.send(JSON.stringify({
          type: 'SEEK',
          payload: { t: compensated }
        }));
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
      setTimeout(() => {
        if (rooms.get(currentRoom.id)?.members.size === 0) rooms.delete(currentRoom.id);
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
app.get('/api/room/new', (req, res) => {
  res.json({ roomId: generateRoomCode() });
});

app.get('/api/room/:id', (req, res) => {
  const room = rooms.get(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  res.json({ exists: true, memberCount: room.members.size });
});

app.get('/api/yt/search', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json({ items: [] });
  try {
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

app.get('/api/yt/info', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'No URL' });
  try {
    const oembed = `https://www.youtube.com/oembed?url=${encodeURIComponent(url)}&format=json`;
    const r = await fetch(oembed);
    if (!r.ok) throw new Error('Not found');
    const data = await r.json();
    res.json({ title: data.title, thumb: data.thumbnail_url, author: data.author_name });
  } catch (e) {
    res.status(404).json({ error: 'Video not found or unavailable' });
  }
});

function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'WAVE-' + Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ─────────────────────────────────────────
// HEARTBEAT — SYNC_TICK every 1.5s to ALL members
// Each client uses this to do soft drift correction.
// Sending to everyone (not just guests) keeps all
// clients honest and detects any de-sync.
// ─────────────────────────────────────────
setInterval(() => {
  rooms.forEach(room => {
    if (!room.video || room.members.size < 2) return;
    room.members.forEach(member => {
      sendStateToMember(room, member, 'SYNC_TICK');
    });
  });
}, 1500);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`WaveWatch running on port ${PORT}`));
