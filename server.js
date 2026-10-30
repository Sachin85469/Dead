const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true }, maxHttpBufferSize: 1e5 });
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '.deadshot-data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');
const rooms = new Map();
const weapons = {
  rifle: { damage: 34, fireRate: 110, pellets: 1, spread: 0.02, magSize: 30, reserve: 120 },
  sniper: { damage: 78, fireRate: 950, pellets: 1, spread: 0.003, magSize: 5, reserve: 25 },
  shotgun: { damage: 22, fireRate: 750, pellets: 8, spread: 0.08, magSize: 8, reserve: 32 },
  smg: { damage: 24, fireRate: 70, pellets: 1, spread: 0.038, magSize: 33, reserve: 132 }
};
const obstacles = [
  { x: -20, z: -15, w: 10, h: 4.5, d: 18 }, { x: 22, z: 18, w: 10, h: 4.5, d: 18 },
  { x: -25, z: 20, w: 15, h: 4.5, d: 9 }, { x: 25, z: -22, w: 14, h: 4.5, d: 12 },
  { x: 0, z: -40, w: 6, h: 4.5, d: 14 }, { x: 0, z: 40, w: 6, h: 4.5, d: 14 },
  { x: 0, z: 0, w: 16, h: 4.2, d: 16 },
  { x: -9, z: 11, w: 2.4, h: 4.8, d: 2.4 }, { x: 11, z: -9, w: 2.4, h: 2.4, d: 2.4 },
  { x: 13.5, z: -9, w: 2.4, h: 2.4, d: 2.4 }, { x: -2, z: -16, w: 2.4, h: 2.4, d: 2.4 },
  { x: 2, z: 16, w: 2.4, h: 2.4, d: 2.4 }, { x: -30, z: -5, w: 2.4, h: 2.4, d: 2.4 },
  { x: 30, z: 5, w: 2.4, h: 2.4, d: 2.4 }
];

app.use(express.json({ limit: '20kb' }));
app.use(express.static(__dirname, { index: 'index.html' }));
app.get('/api/health', (_req, res) => res.json({ ok: true, activeRooms: rooms.size }));

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (err) { if (err.code !== 'ENOENT') console.error('Could not read accounts:', err.message); return {}; }
}
function writeUsers(users) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const temp = `${USERS_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(users, null, 2), { mode: 0o600 });
  fs.renameSync(temp, USERS_FILE);
}
function signSession(user) {
  const payload = Buffer.from(JSON.stringify({ sub: user.email, name: user.name, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function sessionUser(token) {
  if (typeof token !== 'string') return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest();
  let actual;
  try { actual = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now() ? { email: data.sub, name: data.name } : null;
  } catch { return null; }
}
function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve({ salt, hash: key.toString('hex') })));
}

app.post('/api/account/register', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const name = cleanName(String(req.body.name || '').trim().slice(0, 15) || email.split('@')[0].slice(0, 15) || 'Operative');
  const password = String(req.body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8 || password.length > 200) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const users = readUsers();
  if (users[email]) return res.status(409).json({ error: 'An account with that email already exists.' });
  const credentials = await passwordHash(password);
  users[email] = { email, name, ...credentials, createdAt: new Date().toISOString() };
  writeUsers(users);
  return res.json({ token: signSession(users[email]), name });
});

app.post('/api/account/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = readUsers()[email];
  if (!user) return res.status(401).json({ error: 'Email or password is incorrect.' });
  const calculated = await passwordHash(password, user.salt);
  const a = Buffer.from(calculated.hash, 'hex');
  const b = Buffer.from(user.hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Email or password is incorrect.' });
  return res.json({ token: signSession(user), name: user.name });
});

function cleanName(value) {
  return String(value || 'Operative').replace(/[<>\u0000-\u001f]/g, '').trim().slice(0, 15) || 'Operative';
}
function roomCode() {
  let code;
  do { code = crypto.randomBytes(3).toString('hex').toUpperCase(); } while (rooms.has(code));
  return code;
}
function spawnFor(team) {
  return { x: (Math.random() - 0.5) * 28, y: 1.82, z: team === 'blue' ? 48 : -48 };
}
function safePlayer(player) {
  const { id, name, team, ready, isAlive, health, kills, deaths, weapon, x, y, z, yaw, pitch, score, ammo, reserve, isHost } = player;
  return { id, name, team, ready, isAlive, health, kills, deaths, weapon, x, y, z, yaw, pitch, score, ammo, reserve, isHost };
}
function roomPayload(room) {
  return { code: room.code, phase: room.phase, hostId: room.hostId, blueScore: room.blueScore, redScore: room.redScore,
    timeRemaining: room.phase === 'running' ? Math.max(0, Math.ceil((room.endsAt - Date.now()) / 1000)) : 600,
    players: [...room.players.values()].map(p => ({ ...safePlayer(p), isHost: p.id === room.hostId })) };
}
function publishRoom(room) {
  io.to(room.code).emit('room:update', roomPayload(room));
}
function emitError(socket, message) { socket.emit('game:error', { message }); }
function teamCount(room, team) { return [...room.players.values()].filter(p => p.team === team).length; }
function blockedPosition(x, y, z) {
  if (Math.abs(x) > 80 || Math.abs(z) > 80) return true;
  return obstacles.some(obstacle => y < obstacle.h + 0.15 &&
    x > obstacle.x - obstacle.w / 2 - 0.52 && x < obstacle.x + obstacle.w / 2 + 0.52 &&
    z > obstacle.z - obstacle.d / 2 - 0.52 && z < obstacle.z + obstacle.d / 2 + 0.52);
}
function placePlayer(player, team = player.team) {
  const spawn = spawnFor(team);
  Object.assign(player, spawn, { health: 100, isAlive: true, respawnAt: 0, yaw: team === 'blue' ? 0 : Math.PI, pitch: 0 });
}
function maybeFinish(room) {
  if (room.phase !== 'running') return;
  room.phase = 'finished';
  room.finishedAt = Date.now();
  io.to(room.code).emit('game:ended', { ...roomPayload(room), winner: room.blueScore === room.redScore ? 'draw' : (room.blueScore > room.redScore ? 'blue' : 'red') });
  publishRoom(room);
}

io.on('connection', socket => {
  socket.on('room:create', data => {
    const name = cleanName(data && data.name);
    const team = data && data.team === 'red' ? 'red' : 'blue';
    const account = sessionUser(data && data.token);
    const code = roomCode();
    const player = { id: socket.id, name: account ? account.name : name, account: account && account.email, team, ready: false,
      isAlive: true, health: 100, kills: 0, deaths: 0, score: 0, weapon: weapons[data && data.weapon] ? data.weapon : 'rifle',
      x: 0, y: 1.82, z: 0, yaw: team === 'blue' ? Math.PI : 0, pitch: 0, lastMoveAt: Date.now(), lastShotAt: 0,
      ammo: weapons[data && data.weapon] ? weapons[data.weapon].magSize : weapons.rifle.magSize, reserve: weapons[data && data.weapon] ? weapons[data.weapon].reserve : weapons.rifle.reserve, reloadUntil: 0 };
    placePlayer(player, team);
    const room = { code, hostId: socket.id, phase: 'lobby', players: new Map([[socket.id, player]]), blueScore: 0, redScore: 0, endsAt: 0 };
    rooms.set(code, room);
    socket.data.roomCode = code;
    socket.join(code);
    socket.emit('room:joined', { id: socket.id, code });
    publishRoom(room);
  });

  socket.on('room:join', data => {
    const code = String(data && data.code || '').trim().toUpperCase();
    const room = rooms.get(code);
    if (!room) return emitError(socket, 'That room was not found. Check the code and try again.');
    if (room.phase !== 'lobby') return emitError(socket, 'That match has already started.');
    if (room.players.size >= 16) return emitError(socket, 'This room is full (8 players per team).');
    const team = data && data.team === 'red' ? 'red' : 'blue';
    if (teamCount(room, team) >= 8) return emitError(socket, `${team === 'blue' ? 'Blue' : 'Red'} team is full. Switch teams and try again.`);
    const account = sessionUser(data && data.token);
    const weapon = weapons[data && data.weapon] ? data.weapon : 'rifle';
    const player = { id: socket.id, name: account ? account.name : cleanName(data && data.name), account: account && account.email, team, ready: false,
      isAlive: true, health: 100, kills: 0, deaths: 0, score: 0, weapon, ...spawnFor(team), yaw: team === 'blue' ? 0 : Math.PI, pitch: 0,
      lastMoveAt: Date.now(), lastShotAt: 0, ammo: weapons[weapon].magSize, reserve: weapons[weapon].reserve, reloadUntil: 0 };
    room.players.set(socket.id, player);
    socket.data.roomCode = code;
    socket.join(code);
    socket.emit('room:joined', { id: socket.id, code });
    publishRoom(room);
  });

  socket.on('room:team', team => {
    const room = rooms.get(socket.data.roomCode);
    const player = room && room.players.get(socket.id);
    if (!room || !player || room.phase !== 'lobby' || !['blue', 'red'].includes(team) || player.team === team) return;
    if (teamCount(room, team) >= 8) return emitError(socket, 'That team is full.');
    player.team = team;
    player.ready = false;
    placePlayer(player, team);
    publishRoom(room);
  });

  socket.on('room:ready', payload => {
    const room = rooms.get(socket.data.roomCode);
    const player = room && room.players.get(socket.id);
    if (!room || !player || room.phase !== 'lobby') return;
    player.ready = Boolean(payload && payload.ready);
    if (weapons[payload && payload.weapon]) player.weapon = payload.weapon;
    publishRoom(room);
  });

  socket.on('room:start', () => {
    const room = rooms.get(socket.data.roomCode);
    if (!room || room.hostId !== socket.id || room.phase !== 'lobby') return;
    const players = [...room.players.values()];
    if (players.length < 2 || !teamCount(room, 'blue') || !teamCount(room, 'red')) return emitError(socket, 'At least two players must join, with a player on each team.');
    if (players.some(p => !p.ready)) return emitError(socket, 'Everyone must be ready before the host can start.');
    room.phase = 'running';
    room.blueScore = 0;
    room.redScore = 0;
    room.endsAt = Date.now() + 10 * 60 * 1000;
    for (const p of players) {
      p.kills = 0; p.deaths = 0; p.score = 0; p.ready = true;
      p.ammo = weapons[p.weapon].magSize; p.reserve = weapons[p.weapon].reserve;
      placePlayer(p);
    }
    io.to(room.code).emit('game:started', roomPayload(room));
    publishRoom(room);
  });

  socket.on('player:state', state => {
    const room = rooms.get(socket.data.roomCode);
    const player = room && room.players.get(socket.id);
    if (!room || room.phase !== 'running' || !player || !player.isAlive || !state) return;
    const x = Number(state.x), y = Number(state.y), z = Number(state.z), yaw = Number(state.yaw), pitch = Number(state.pitch);
    if (![x, y, z, yaw, pitch].every(Number.isFinite) || Math.abs(x) > 82 || Math.abs(z) > 82 || y < 0.8 || y > 4 || blockedPosition(x, y, z)) return;
    const now = Date.now();
    const elapsed = Math.min(250, Math.max(16, now - player.lastMoveAt));
    const distance = Math.hypot(x - player.x, z - player.z);
    if (distance > 0.8 + elapsed * 0.018 || Math.abs(y - player.y) > 0.3 + elapsed * 0.012) return;
    player.x = x; player.y = y; player.z = z;
    player.yaw = Math.atan2(Math.sin(yaw), Math.cos(yaw));
    player.pitch = Math.max(-1.56, Math.min(1.56, pitch));
    player.lastMoveAt = now;
  });

  socket.on('weapon:select', weapon => {
    const room = rooms.get(socket.data.roomCode);
    const player = room && room.players.get(socket.id);
    if (!room || !player || !weapons[weapon] || (room.phase === 'running' && player.isAlive)) return;
    player.weapon = weapon;
    player.ammo = weapons[weapon].magSize;
    player.reserve = weapons[weapon].reserve;
    publishRoom(room);
  });

  socket.on('weapon:reload', () => {
    const room = rooms.get(socket.data.roomCode);
    const player = room && room.players.get(socket.id);
    if (!room || !player || !player.isAlive) return;
    const gun = weapons[player.weapon];
    if (player.reloadUntil > Date.now() || player.ammo >= gun.magSize || player.reserve <= 0) return;
    player.reloadUntil = Date.now() + 1100;
  });

  socket.on('fire:shot', payload => {
    const room = rooms.get(socket.data.roomCode);
    const shooter = room && room.players.get(socket.id);
    if (!room || room.phase !== 'running' || !shooter || !shooter.isAlive) return;
    const gun = weapons[shooter.weapon];
    const now = Date.now();
    if (shooter.reloadUntil > now || now - shooter.lastShotAt < gun.fireRate || shooter.ammo <= 0) return;
    const directions = Array.isArray(payload && payload.directions) ? payload.directions.slice(0, gun.pellets) : [];
    if (!directions.length) return;
    const dirs = directions.map(d => {
      if (!d || ![d.x, d.y, d.z].every(Number.isFinite)) return null;
      const length = Math.hypot(d.x, d.y, d.z);
      if (length < 0.9 || length > 1.1) return null;
      return { x: d.x / length, y: d.y / length, z: d.z / length };
    });
    if (dirs.some(d => !d)) return;
    const expected = { x: Math.sin(shooter.yaw) * Math.cos(shooter.pitch), y: -Math.sin(shooter.pitch), z: -Math.cos(shooter.yaw) * Math.cos(shooter.pitch) };
    const maxSpread = Math.sqrt(2) * gun.spread + 0.035;
    if (dirs.some(d => d.x * expected.x + d.y * expected.y + d.z * expected.z < Math.cos(maxSpread))) return;
    shooter.lastShotAt = now;
    shooter.ammo--;
    const results = [];
    let hitAny = false;
    for (const dir of dirs) {
      let closest = 180;
      let targetHit = null;
      let headshot = false;
      const origin = { x: shooter.x, y: shooter.y - 0.04, z: shooter.z };
      let nearestWall = 180;
      for (const obstacle of obstacles) {
        const wallDistance = rayBoxDistance(origin, dir, { min: { x: obstacle.x - obstacle.w / 2, y: 0, z: obstacle.z - obstacle.d / 2 }, max: { x: obstacle.x + obstacle.w / 2, y: obstacle.h, z: obstacle.z + obstacle.d / 2 } });
        if (wallDistance !== null) nearestWall = Math.min(nearestWall, wallDistance);
      }
      for (const target of room.players.values()) {
        if (!target.isAlive || target.team === shooter.team || target.id === shooter.id) continue;
        const box = { min: { x: target.x - 0.38, y: target.y - 1.72, z: target.z - 0.38 }, max: { x: target.x + 0.38, y: target.y - 0.04, z: target.z + 0.38 } };
        const dist = rayBoxDistance(origin, dir, box);
        if (dist !== null && dist < closest && dist < nearestWall) {
          closest = dist; targetHit = target;
          const hitY = shooter.y - 0.04 + dir.y * dist;
          headshot = hitY > target.y - 0.56;
        }
      }
      if (targetHit) {
        const amount = gun.damage * (headshot ? 1.6 : 1);
        targetHit.health = Math.max(0, targetHit.health - amount);
        hitAny = true;
        results.push({ victimId: targetHit.id, headshot });
        io.to(targetHit.id).emit('player:damaged', { health: targetHit.health, from: shooter.name });
        if (targetHit.health <= 0) eliminate(room, shooter, targetHit, headshot);
      }
    }
    const maxDistance = results.length ? 180 : 180;
    io.to(room.code).emit('player:shot', { id: shooter.id, name: shooter.name, team: shooter.team, weapon: shooter.weapon,
      origin: { x: shooter.x, y: shooter.y - 0.12, z: shooter.z }, directions: dirs, range: maxDistance });
    socket.emit('shot:result', { hit: hitAny, headshot: results.some(r => r.headshot) });
    publishRoom(room);
  });

  socket.on('room:leave', () => leaveRoom(socket));
  socket.on('disconnect', () => leaveRoom(socket));

  function leaveRoom(currentSocket) {
    const code = currentSocket.data.roomCode;
    const room = rooms.get(code);
    if (!room || !room.players.has(currentSocket.id)) return;
    room.players.delete(currentSocket.id);
    currentSocket.leave(code);
    currentSocket.data.roomCode = null;
    if (!room.players.size) { rooms.delete(code); return; }
    if (room.hostId === currentSocket.id) room.hostId = room.players.keys().next().value;
    publishRoom(room);
  }
});

function rayBoxDistance(origin, direction, box) {
  let tmin = 0, tmax = 180;
  for (const axis of ['x', 'y', 'z']) {
    const d = direction[axis];
    if (Math.abs(d) < 1e-7) {
      if (origin[axis] < box.min[axis] || origin[axis] > box.max[axis]) return null;
      continue;
    }
    let a = (box.min[axis] - origin[axis]) / d;
    let b = (box.max[axis] - origin[axis]) / d;
    if (a > b) [a, b] = [b, a];
    tmin = Math.max(tmin, a);
    tmax = Math.min(tmax, b);
    if (tmin > tmax) return null;
  }
  return tmin <= 180 ? tmin : null;
}

function eliminate(room, killer, victim, headshot) {
  if (!victim.isAlive) return;
  victim.isAlive = false;
  victim.health = 0;
  victim.deaths++;
  victim.respawnAt = Date.now() + 3500;
  killer.kills++;
  killer.score += headshot ? 150 : 100;
  if (killer.team === 'blue') room.blueScore++;
  else room.redScore++;
  io.to(victim.id).emit('player:eliminated', { killer: killer.name, respawnAt: victim.respawnAt });
  io.to(room.code).emit('game:kill', { killer: killer.name, killerTeam: killer.team, victim: victim.name, weapon: killer.weapon, headshot, blueScore: room.blueScore, redScore: room.redScore });
  publishRoom(room);
  setTimeout(() => {
    const current = rooms.get(room.code);
    const player = current && current.players.get(victim.id);
    if (!player || player.isAlive || current.phase !== 'running') return;
    placePlayer(player);
    player.ammo = weapons[player.weapon].magSize;
    player.reserve = weapons[player.weapon].reserve;
    io.to(player.id).emit('player:respawned', { x: player.x, y: player.y, z: player.z, yaw: player.yaw, weapon: player.weapon });
    publishRoom(current);
  }, 3500);
}

setInterval(() => {
  for (const room of rooms.values()) {
    const now = Date.now();
    for (const player of room.players.values()) {
      if (player.reloadUntil && player.reloadUntil <= now) {
        const gun = weapons[player.weapon];
        const amount = Math.min(gun.magSize - player.ammo, player.reserve);
        player.ammo += amount; player.reserve -= amount; player.reloadUntil = 0;
      }
    }
    if (room.phase === 'running' && room.endsAt <= now) maybeFinish(room);
    if (room.phase === 'running') publishRoom(room);
    if (room.phase === 'finished' && now - room.finishedAt > 5 * 60 * 1000 && room.players.size === 0) rooms.delete(room.code);
  }
}, 100);

server.listen(PORT, '0.0.0.0', () => console.log(`Deadshot multiplayer server listening on ${PORT}`));

