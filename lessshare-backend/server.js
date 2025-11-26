require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt'); // 👈 Add bcrypt for password hashing

const app = express();
const server = http.createServer(app);

console.log("---------------------------------")
console.log(`origin: ${process.env.CORS_ORIGINS.split(',')}`)
console.log("---------------------------------")

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true
  }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Mongoose Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 20 },
  isAdmin: { type: Boolean, default: false },
  password: { 
    type: String, 
    required: function() { return this.isAdmin; } // 👈 Required only for admins
  }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const roomSchema = new mongoose.Schema({
  roomId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
  fileCount: { type: Number, default: 0 },
  files: [{
    fileName: { type: String, required: true },
    fileType: { type: String, required: true },
    fileSize: { type: Number, required: true },
    senderPeerId: { type: String, required: true },
    sharedAt: { type: Date, required: true }
  }],
  status: { type: String, default: 'ACTIVE' },
  peers: [{ type: String }],
  messages: [{
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    senderUsername: { type: String, required: true },
    content: { type: String, required: true, maxlength: 1000 },
    sentAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const Room = mongoose.model('Room', roomSchema);

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log(`Invalid token: ${err.message}`);
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to check if user is admin
const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user || !user.isAdmin) {
      console.log(`Unauthorized admin access attempt by ${req.user.userId}`);
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (err) {
    console.error(`Error checking admin status: ${err.message}`);
    res.status(500).json({ error: 'Failed to verify admin status' });
  }
};

// API Endpoints
app.post('/api/users', async (req, res) => {
  const { username } = req.body;
  if (!username || username.length < 3 || username.length > 20) {
    console.log(`Invalid username: ${username}`);
    return res.status(400).json({ error: 'Username must be 3-20 characters' });
  }

  try {
    let user = await User.findOne({ username });
    if (!user) {
      user = new User({ username, isAdmin: false }); // 👈 isAdmin forced to false
      await user.save();
      console.log(`Created new user: ${username} (${user._id})`);
    } else {
      console.log(`User already exists: ${username} (${user._id})`);
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ user: { id: user._id, username: user.username, isAdmin: user.isAdmin }, token });
  } catch (err) {
    console.error(`Error processing user: ${err.message}`);
    res.status(500).json({ error: 'Failed to process user' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    console.log('Username and password required');
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      console.log(`User not found: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!user.isAdmin) {
      console.log(`Non-admin user attempted admin login: ${username}`);
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (!user.password || !(await bcrypt.compare(password, user.password))) {
      console.log(`Invalid password for user: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    console.log(`Admin login successful: ${username} (${user._id})`);
    res.json({ user: { id: user._id, username: user.username, isAdmin: user.isAdmin }, token });
  } catch (err) {
    console.error(`Error during admin login: ${err.message}`);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('username isAdmin');
    if (!user) {
      console.log(`User not found: ${req.user.userId}`);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ id: user._id, username: user.username, isAdmin: user.isAdmin });
  } catch (err) {
    console.error(`Error fetching user: ${err.message}`);
    res.status(500).json({ error: 'Failed to fetch user info' });
  }
});

app.delete('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId);
    if (!user) {
      console.log(`User not found: ${userId}`);
      return res.status(404).json({ error: 'User not found' });
    }

    await Room.deleteMany({ creatorId: userId });
    await User.findByIdAndDelete(userId);

    console.log(`Deleted user: ${user.username} (${userId}) and their rooms`);
    res.json({ success: true });
  } catch (err) {
    console.error(`Error deleting user: ${err.message}`);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/users/:id/rooms', authenticateToken, async (req, res) => {
  try {
    if (req.user.userId !== req.params.id) {
      console.log(`Unauthorized access by ${req.user.userId} for ${req.params.id}`);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const userRooms = await Room.find({ creatorId: req.params.id });
    res.json(userRooms);
  } catch (err) {
    console.error(`Error fetching rooms: ${err.message}`);
    res.status(500).json({ error: 'Failed to fetch rooms' });
  }
});

app.post('/api/rooms', authenticateToken, async (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    console.log('Room name is required');
    return res.status(400).json({ error: 'Room name is required' });
  }

  try {
    const newRoom = new Room({
      roomId: uuidv4(),
      name: name.trim(),
      creatorId: req.user.userId
    });
    await newRoom.save();
    console.log(`Created room: ${newRoom.name} (${newRoom.roomId})`);
    res.status(201).json(newRoom);
  } catch (err) {
    console.error(`Error creating room: ${err.message}`);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

app.get('/api/rooms/:roomId', authenticateToken, async (req, res) => {
  const { roomId } = req.params;
  try {
    const room = await Room.findOne({ roomId }).populate('messages.senderId', 'username');
    if (!room) {
      console.log(`Room not found: ${roomId}`);
      return res.status(404).json({ error: 'Room not found' });
    }
    console.log(`[GET /api/rooms/${roomId}] Returning room data with ${room.files.length} files and ${room.messages.length} messages`);
    res.json({
      roomId: room.roomId,
      creatorPeerId: room.creatorPeerId,
      peers: room.peers,
      fileCount: room.fileCount,
      files: room.files,
      messages: room.messages.map(msg => ({
        id: msg._id,
        senderId: msg.senderId._id,
        senderUsername: msg.senderUsername,
        content: msg.content,
        sentAt: msg.sentAt
      }))
    });
  } catch (err) {
    console.error(`[GET /api/rooms/${roomId}] Error:`, err);
    res.status(500).json({ error: 'Failed to fetch room' });
  }
});

app.put('/api/rooms/:roomId/peers', authenticateToken, async (req, res) => {
  const { peerId } = req.body;
  const { roomId } = req.params;

  if (!peerId || typeof peerId !== 'string') {
    console.log(`Invalid peerId: ${peerId}`);
    return res.status(400).json({ error: 'Valid peerId is required' });
  }

  try {
    const room = await Room.findOne({ roomId });
    if (!room) {
      console.log(`Room not found: ${roomId}`);
      return res.status(404).json({ error: 'Room not found' });
    }

    if (!room.peers.includes(peerId)) {
      room.peers.push(peerId);
      await room.save();
      console.log(`Added peer ${peerId} to room ${roomId}`);
    } else {
      console.log(`Peer ${peerId} already in room ${roomId}`);
    }

    res.json({ success: true, peers: room.peers });
  } catch (err) {
    console.error(`Error adding peer to room: ${err.message}`);
    res.status(500).json({ error: 'Failed to add peer' });
  }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('username isAdmin createdAt');
    res.json(users);
  } catch (err) {
    console.error(`Error fetching users: ${err.message}`);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/rooms', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const rooms = await Room.find().populate('creatorId', 'username');
    res.json(rooms);
  } catch (err) {
    console.error(`Error fetching rooms: ${err.message}`);
    res.status(500).json({ error: 'Failed to fetch rooms' });
  }
});

// Socket.IO setup
const roomsPeers = {};

io.on('connection', (socket) => {
  let currentRoom = null;
  let peerId = null;
  let userId = null;

  socket.on('auth', async ({ token }, callback) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.userId;
      const user = await User.findById(userId).select('username isAdmin');
      if (!user) {
        console.log(`User not found for socket auth: ${userId}`);
        return callback({ success: false, error: 'User not found' });
      }
      console.log(`[socket ${socket.id}] Authenticated user: ${user.username} (${userId}, isAdmin: ${user.isAdmin})`);
      callback({ success: true, user: { id: user._id, username: user.username, isAdmin: user.isAdmin } });
    } catch (err) {
      console.error(`[socket ${socket.id}] Authentication error:`, err);
      callback({ success: false, error: 'Invalid token' });
    }
  });

  socket.on('join-room', (roomId, callback) => {
    if (!userId) {
      console.log(`[socket ${socket.id}] Unauthorized join-room attempt`);
      return callback({ success: false, error: 'Authentication required' });
    }

    if (!roomsPeers[roomId]) {
      roomsPeers[roomId] = new Set();
    }

    peerId = socket.id;
    currentRoom = roomId;
    roomsPeers[roomId].add(peerId);
    socket.join(roomId);

    console.log(`[socket ${socket.id}, peer ${peerId}] Peer ${peerId} joined room ${roomId}, peers: ${roomsPeers[roomId].size}`);

    if (typeof callback === 'function') {
      const creatorPeerId = roomsPeers[roomId].values().next().value;
      callback({
        success: true,
        peerId,
        peers: Array.from(roomsPeers[roomId]).filter(id => id !== peerId),
        creatorPeerId
      });
    }

    socket.to(roomId).emit('peer-connected', peerId);
  });

  socket.on('chat-message', async ({ roomId, content }, callback) => {
    if (!userId) {
      console.log(`[socket ${socket.id}] Unauthorized chat-message attempt`);
      return callback?.({ success: false, error: 'Authentication required' });
    }
    if (!content || typeof content !== 'string' || content.trim().length === 0 || content.length > 1000) {
      console.log(`[socket ${socket.id}] Invalid chat message`);
      return callback?.({ success: false, error: 'Invalid message content' });
    }

    try {
      const user = await User.findById(userId).select('username');
      if (!user) {
        console.log(`[socket ${socket.id}] User not found: ${userId}`);
        return callback?.({ success: false, error: 'User not found' });
      }

      const message = {
        senderId: userId,
        senderUsername: user.username,
        content: content.trim(),
        sentAt: new Date()
      };

      const updatedRoom = await Room.findOneAndUpdate(
        { roomId },
        { $push: { messages: message } },
        { new: true }
      );

      if (!updatedRoom) {
        console.log(`[socket ${socket.id}] Room not found: ${roomId}`);
        return callback?.({ success: false, error: 'Room not found' });
      }

      console.log(`[socket ${socket.id}] Broadcasting chat message in room ${roomId} from ${user.username}`);
      io.to(roomId).emit('chat-message', {
        id: updatedRoom.messages[updatedRoom.messages.length - 1]._id,
        senderId: userId,
        senderUsername: user.username,
        content: message.content,
        sentAt: message.sentAt
      });

      callback?.({ success: true });
    } catch (err) {
      console.error(`[socket ${socket.id}] Error saving chat message:`, err);
      callback?.({ success: false, error: 'Failed to send message' });
    }
  });

  socket.on('signal', ({ to, from, data }) => {
    console.log(`[socket ${socket.id}, peer ${from}] Relaying signal from ${from} to ${to}: ${data.type}`);
    socket.to(to).emit('signal', { from, data });
  });

  socket.on('leave-room', (roomId) => {
    if (roomsPeers[roomId]) {
      roomsPeers[roomId].delete(peerId);
      socket.to(roomId).emit('peer-disconnected', peerId);
      socket.leave(roomId);
      console.log(`[socket ${socket.id}, peer ${peerId}] Peer ${peerId} left room ${roomId}, peers: ${roomsPeers[roomId].size}`);
      if (roomsPeers[roomId].size === 0) {
        delete roomsPeers[roomId];
      }
    }
  });

  socket.on('file-metadata', async (event) => {
    try {
      const { roomId, metadata } = event;
      console.log(`[socket ${socket.id}] Broadcasting file-metadata in room ${roomId}`);

      const fileData = {
        fileName: metadata.fileName,
        fileType: metadata.fileType,
        fileSize: metadata.fileSize,
        senderPeerId: socket.id,
        sharedAt: new Date()
      };

      const updatedRoom = await Room.findOneAndUpdate(
        { roomId },
        {
          $push: { files: fileData },
          $inc: { fileCount: 1 }
        },
        { new: true }
      );

      if (!updatedRoom) {
        console.error(`Room ${roomId} not found`);
        return;
      }

      io.to(roomId).emit('file-metadata', metadata, socket.id);
    } catch (err) {
      console.error(`[socket ${socket.id}] Error saving file metadata:`, err);
    }
  });

  socket.on('file-chunk', ({ roomId, chunk }) => {
    console.log(`[socket ${socket.id}] Broadcasting file-chunk in room ${roomId}`);
    socket.to(roomId).emit('file-chunk', chunk);
  });

  socket.on('file-complete', (roomId) => {
    console.log(`[socket ${socket.id}] Broadcasting file-complete in room ${roomId}`);
    socket.to(roomId).emit('file-complete');
  });

  socket.on('disconnect', () => {
    if (currentRoom && roomsPeers[currentRoom]) {
      roomsPeers[currentRoom].delete(peerId);
      socket.to(currentRoom).emit('peer-disconnected', peerId);
      console.log(`[socket ${socket.id}, peer ${peerId}] Peer ${peerId} disconnected from room ${currentRoom}, peers: ${roomsPeers[currentRoom]?.size || 0}`);
      if (roomsPeers[currentRoom]?.size === 0) {
        delete roomsPeers[currentRoom];
      }
    }
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(`Server error: ${err.stack}`);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});