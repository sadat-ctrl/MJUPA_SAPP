const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'zanachat-secret-2024';
const PORT = process.env.PORT || 3000;

const db = new Database('chatapp.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, avatar TEXT DEFAULT NULL,
    status TEXT DEFAULT 'Habari!', last_seen INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    is_group INTEGER DEFAULT 0, avatar TEXT DEFAULT NULL,
    created_by TEXT, created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS room_members (
    room_id TEXT NOT NULL, user_id TEXT NOT NULL,
    PRIMARY KEY (room_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, room_id TEXT NOT NULL,
    sender_id TEXT NOT NULL, content TEXT NOT NULL,
    type TEXT DEFAULT 'text', created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Hakuna ruhusa' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token batili' }); }
}

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Jaza taarifa zote' });
  if (username.length < 3) return res.status(400).json({ error: 'Jina liwe na herufi 3+' });
  if (password.length < 6) return res.status(400).json({ error: 'Nywila iwe na herufi 6+' });
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) return res.status(400).json({ error: 'Jina hili limetumika tayari' });
  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();
  db.prepare('INSERT INTO users (id, username, password) VALUES (?, ?, ?)').run(id, username, hashed);
  const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id, username, status: 'Habari!', avatar: null } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(400).json({ error: 'Jina au nywila si sahihi' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Jina au nywila si sahihi' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, status: user.status, avatar: user.avatar } });
});

app.get('/api/users', authMiddleware, (req, res) => {
  const users = db.prepare('SELECT id, username, status, avatar, last_seen FROM users WHERE id != ?').all(req.user.id);
  res.json(users);
});

app.put('/api/profile', authMiddleware, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, req.user.id);
  res.json({ success: true });
});

app.get('/api/rooms', authMiddleware, (req, res) => {
  const rooms = db.prepare(`
    SELECT r.*, 
      (SELECT content FROM messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message_time
    FROM rooms r
    INNER JOIN room_members rm ON rm.room_id = r.id
    WHERE rm.user_id = ?
    ORDER BY last_message_time DESC
  `).all(req.user.id);

  const enriched = rooms.map(room => {
    if (!room.is_group) {
      const other = db.prepare(`
        SELECT u.id, u.username, u.avatar, u.status, u.last_seen FROM users u
        INNER JOIN room_members rm ON rm.user_id = u.id
        WHERE rm.room_id = ? AND u.id != ?
      `).get(room.id, req.user.id);
      return { ...room, other_user: other };
    }
    const members = db.prepare(`
      SELECT u.id, u.username, u.avatar FROM users u
      INNER JOIN room_members rm ON rm.user_id = u.id WHERE rm.room_id = ?
    `).all(room.id);
    return { ...room, members };
  });
  res.json(enriched);
});

app.post('/api/rooms/dm', authMiddleware, (req, res) => {
  const { user_id } = req.body;
  const existing = db.prepare(`
    SELECT r.id FROM rooms r
    INNER JOIN room_members rm1 ON rm1.room_id = r.id AND rm1.user_id = ?
    INNER JOIN room_members rm2 ON rm2.room_id = r.id AND rm2.user_id = ?
    WHERE r.is_group = 0
  `).get(req.user.id, user_id);
  if (existing) return res.json({ room_id: existing.id });
  const roomId = uuidv4();
  db.prepare('INSERT INTO rooms (id, name, is_group, created_by) VALUES (?, ?, 0, ?)').run(roomId, 'dm', req.user.id);
  db.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').run(roomId, req.user.id);
  db.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').run(roomId, user_id);
  res.json({ room_id: roomId });
});

app.post('/api/rooms/group', authMiddleware, (req, res) => {
  const { name, member_ids } = req.body;
  if (!name) return res.status(400).json({ error: 'Weka jina la kikundi' });
  const roomId = uuidv4();
  db.prepare('INSERT INTO rooms (id, name, is_group, created_by) VALUES (?, ?, 1, ?)').run(roomId, name, req.user.id);
  db.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').run(roomId, req.user.id);
  const allMembers = [...new Set([...(member_ids || [])])];
  for (const uid of allMembers) {
    if (uid !== req.user.id)
      db.prepare('INSERT OR IGNORE INTO room_members (room_id, user_id) VALUES (?, ?)').run(roomId, uid);
  }
  res.json({ room_id: roomId });
});

app.get('/api/rooms/:roomId/messages', authMiddleware, (req, res) => {
  const member = db.prepare('SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?').get(req.params.roomId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Huna ruhusa' });
  const messages = db.prepare(`
    SELECT m.*, u.username, u.avatar FROM messages m
    INNER JOIN users u ON u.id = m.sender_id
    WHERE m.room_id = ? ORDER BY m.created_at ASC LIMIT 100
  `).all(req.params.roomId);
  res.json(messages);
});

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Hakuna faili' });
  res.json({ url: '/uploads/' + req.file.filename });
});

const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Unauthorized')); }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  onlineUsers.set(userId, socket.id);
  db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(Date.now(), userId);
  socket.broadcast.emit('user_online', { user_id: userId });

  const userRooms = db.prepare('SELECT room_id FROM room_members WHERE user_id = ?').all(userId);
  userRooms.forEach(r => socket.join(r.room_id));

  socket.on('send_message', (data) => {
    const { room_id, content, type = 'text' } = data;
    const member = db.prepare('SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?').get(room_id, userId);
    if (!member) return;
    const msgId = uuidv4();
    const timestamp = Date.now();
    db.prepare('INSERT INTO messages (id, room_id, sender_id, content, type, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(msgId, room_id, userId, content, type, timestamp);
    const user = db.prepare('SELECT username, avatar FROM users WHERE id = ?').get(userId);
    io.to(room_id).emit('new_message', { id: msgId, room_id, sender_id: userId, username: user.username, avatar: user.avatar, content, type, created_at: timestamp });
  });

  socket.on('typing', ({ room_id, is_typing }) => {
    socket.to(room_id).emit('user_typing', { user_id: userId, username: socket.user.username, is_typing });
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(userId);
    db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(Date.now(), userId);
    socket.broadcast.emit('user_offline', { user_id: userId });
  });
});

server.listen(PORT, () => console.log(`✅ Server inaendeshwa kwenye port ${PORT}`));
