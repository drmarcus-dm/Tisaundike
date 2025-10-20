// tisaundike.js - Full Music Streaming Platform in ONE FILE
// Run: node tisaundike.js
// Visit: http://localhost:3000

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

// Ensure directories exist
const dirs = ['uploads/audio', 'uploads/covers', 'public'];
dirs.forEach(dir => !fs.existsSync(dir) && fs.mkdirSync(dir, { recursive: true }));

// Database
const db = new sqlite3.Database('tisaundike.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT,
    verified INTEGER DEFAULT 0,
    earnings REAL DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tracks (
    id TEXT PRIMARY KEY,
    title TEXT,
    artist TEXT,
    creatorId TEXT,
    genre TEXT,
    filePath TEXT,
    coverPath TEXT,
    streams INTEGER DEFAULT 0,
    uploadedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(creatorId) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS playlists (
    id TEXT PRIMARY KEY,
    name TEXT,
    userId TEXT,
    trackIds TEXT,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'tisaundike-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, file.fieldname.includes('audio') ? 'uploads/audio' : 'uploads/covers');
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Auth Middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  next();
};
const requireCreator = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'creator') {
    return res.status(403).send('Creators only');
  }
  next();
};

// Routes

// Home
app.get('/', async (req, res) => {
  const tracks = await new Promise((resolve) => {
    db.all('SELECT * FROM tracks ORDER BY streams DESC LIMIT 12', (err, rows) => resolve(rows || []));
  });
  res.render('index', { user: req.session.user, tracks });
});

// Register
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!['listener', 'creator'].includes(role)) return res.status(400).send('Invalid role');

  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (row) return res.render('register', { error: 'Email already exists' });

    db.run('INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
      [id, name, email, hashed, role], (err) => {
        if (err) return res.status(500).send('DB Error');
        res.redirect('/login');
      });
  });
});

// Login
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.redirect('/');
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
  const { user } = req.session;
  if (user.role === 'creator') {
    const tracks = await new Promise(resolve => {
      db.all('SELECT * FROM tracks WHERE creatorId = ?', [user.id], (err, rows) => resolve(rows));
    });
    const totalStreams = tracks.reduce((sum, t) => sum + t.streams, 0);
    const earnings = totalStreams * 0.004; // $0.004 per stream
    res.render('creator-dashboard', { user, tracks, totalStreams, earnings });
  } else {
    const playlists = await new Promise(resolve => {
      db.all('SELECT * FROM playlists WHERE userId = ?', [user.id], (err, rows) => resolve(rows));
    });
    res.render('listener-dashboard', { user, playlists });
  }
});

// Upload Track (Creator Only)
app.get('/upload', requireAuth, requireCreator, (req, res) => res.render('upload', { error: null }));
app.post('/upload', requireAuth, requireCreator, upload.fields([
  { name: 'audio', maxCount: 1 },
  { name: 'cover', maxCount: 1 }
]), (req, res) => {
  const { title, genre } = req.body;
  const audioFile = req.files['audio'][0];
  const coverFile = req.files['cover'][0];
  const creatorId = req.session.user.id;

  if (!audioFile || !title) return res.render('upload', { error: 'Audio & title required' });

  const trackId = uuidv4();
  db.run(`INSERT INTO tracks (id, title, artist, creatorId, genre, filePath, coverPath)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [trackId, title, req.session.user.name, creatorId, genre || 'Unknown',
     `/uploads/audio/${audioFile.filename}`, `/uploads/covers/${coverFile.filename}`],
    (err) => {
      if (err) return res.status(500).send('Upload failed');
      res.redirect('/dashboard');
    });
});

// Stream Track
app.get('/stream/:id', async (req, res) => {
  const track = await new Promise(resolve => {
    db.get('SELECT * FROM tracks WHERE id = ?', [req.params.id], (err, row) => resolve(row));
  });
  if (!track) return res.status(404).send('Track not found');

  // Increment stream count
// tisaundike.js - Full Music Streaming Platform in ONE FILE
// Run: node tisaundike.js
// Visit: http://localhost:3000

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

// Ensure directories exist
const dirs = ['uploads/audio', 'uploads/covers', 'public'];
dirs.forEach(dir => !fs.existsSync(dir) && fs.mkdirSync(dir, { recursive: true }));

// Database
const db = new sqlite3.Database('tisaundike.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT,
    verified INTEGER DEFAULT 0,
    earnings REAL DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tracks (
    id TEXT PRIMARY KEY,
    title TEXT,
    artist TEXT,
    creatorId TEXT,
    genre TEXT,
    filePath TEXT,
    coverPath TEXT,
    streams INTEGER DEFAULT 0,
    uploadedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(creatorId) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS playlists (
    id TEXT PRIMARY KEY,
    name TEXT,
    userId TEXT,
    trackIds TEXT,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'tisaundike-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, file.fieldname.includes('audio') ? 'uploads/audio' : 'uploads/covers');
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Auth Middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  next();
};
const requireCreator = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'creator') {
    return res.status(403).send('Creators only');
  }
  next();
};

// Routes

// Home
app.get('/', async (req, res) => {
  const tracks = await new Promise((resolve) => {
    db.all('SELECT * FROM tracks ORDER BY streams DESC LIMIT 12', (err, rows) => resolve(rows || []));
  });
  res.render('index', { user: req.session.user, tracks });
});

// Register
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!['listener', 'creator'].includes(role)) return res.status(400).send('Invalid role');

  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (row) return res.render('register', { error: 'Email already exists' });

    db.run('INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
      [id, name, email, hashed, role], (err) => {
        if (err) return res.status(500).send('DB Error');
        res.redirect('/login');
      });
  });
});

// Login
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.redirect('/');
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
  const { user } = req.session;
  if (user.role === 'creator') {
    const tracks = await new Promise(resolve => {
      db.all('SELECT * FROM tracks WHERE creatorId = ?', [user.id], (err, rows) => resolve(rows));
    });
    const totalStreams = tracks.reduce((sum, t) => sum + t.streams, 0);
    const earnings = totalStreams * 0.004; // $0.004 per stream
    res.render('creator-dashboard', { user, tracks, totalStreams, earnings });
  } else {
    const playlists = await new Promise(resolve => {
      db.all('SELECT * FROM playlists WHERE userId = ?', [user.id], (err, rows) => resolve(rows));
    });
    res.render('listener-dashboard', { user, playlists });
  }
});

// Upload Track (Creator Only)
app.get('/upload', requireAuth, requireCreator, (req, res) => res.render('upload', { error: null }));
app.post('/upload', requireAuth, requireCreator, upload.fields([
  { name: 'audio', maxCount: 1 },
  { name: 'cover', maxCount: 1 }
]), (req, res) => {
  const { title, genre } = req.body;
  const audioFile = req.files['audio'][0];
  const coverFile = req.files['cover'][0];
  const creatorId = req.session.user.id;

  if (!audioFile || !title) return res.render('upload', { error: 'Audio & title required' });

  const trackId = uuidv4();
  db.run(`INSERT INTO tracks (id, title, artist, creatorId, genre, filePath, coverPath)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [trackId, title, req.session.user.name, creatorId, genre || 'Unknown',
     `/uploads/audio/${audioFile.filename}`, `/uploads/covers/${coverFile.filename}`],
    (err) => {
      if (err) return res.status(500).send('Upload failed');
      res.redirect('/dashboard');
    });
});

// Stream Track
app.get('/stream/:id', async (req, res) => {
  const track = await new Promise(resolve => {
    db.get('SELECT * FROM tracks WHERE id = ?', [req.params.id], (err, row) => resolve(row));
  });
  if (!track) return res.status(404).send('Track not found');

  // Increment stream count
  db.run('UPDATE tracks SET streams = streams + 1 WHERE id = ?', [track.id]);

  // Update creator earnings
  db.run('UPDATE users SET earnings = earnings + 0.004 WHERE id = ?', [track.creatorId]);

  res.render('player', { track, user: req.session.user });
});

// Search
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  const tracks = await new Promise(resolve => {
    db.all(`SELECT * FROM tracks WHERE title LIKE ? OR artist LIKE ?`,
      [`%${q}%`, `%${q}%`], (err, rows) => resolve(rows || []));
  });
  res.render('search', { tracks, query: q, user: req.session.user });
});

// Create Playlist
app.post('/playlist', requireAuth, (req, res) => {
  const { name, trackIds } = req.body;
  const id = uuidv4();
  db.run('INSERT INTO playlists (id, name, userId, trackIds) VALUES (?, ?, ?, ?)',
    [id, name, req.session.user.id, trackIds.join(',')], () => {
      res.redirect('/dashboard');
    });
});

// EJS Templates (Embedded as strings)
const templates = {
  index: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Tisaundike - Stream Music</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <style>body{font-family:'Inter',sans-serif;background:#121212;color:#fff;}</style>
</head>
<body class="min-h-screen">
  <nav class="bg-black p-4 flex justify-between items-center">
    <h1 class="text-2xl font-bold text-green-500">Tisaundike</h1>
    <div>
      <% if (!user) { %>
        <a href="/login" class="text-white mr-4">Login</a>
        <a href="/register" class="bg-green-500 px-4 py-2 rounded text-black">Sign Up</a>
      <% } else { %>
        <a href="/dashboard" class="text-white mr-4"><%= user.name %></a>
        <a href="/logout" class="text-red-400">Logout</a>
      <% } %>
    </div>
  </nav>

  <div class="container mx-auto p-6">
    <h2 class="text-3xl font-bold mb-6">Top Tracks</h2>
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">
      <% tracks.forEach(t => { %>
        <div class="bg-gray-900 p-4 rounded-lg hover:bg-gray-800 transition">
          <img src="<%= t.coverPath %>" alt="cover" class="w-full h-40 object-cover rounded mb-3">
          <h3 class="font-bold"><%= t.title %></h3>
          <p class="text-sm text-gray-400"><%= t.artist %> • <%= t.streams %> streams</p>
          <a href="/stream/<%= t.id %>" class="text-green-500 text-sm mt-2 inline-block">Play →</a>
        </div>
      <% }) %>
    </div>
  </div>
</body>
</html>`,

  register: `<!DOCTYPE html>
<html><head><title>Register - Tisaundike</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
<div class="bg-gray-800 p-8 rounded-lg w-full max-w-md">
  <h1 class="text-2xl font-bold mb-6 text-green-500">Create Account</h1>
  <% if (error) { %><p class="text-red-400 mb-4"><%= error %></p><% } %>
  <form method="POST">
    <input type="text" name="name" placeholder="Full Name" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="email" name="email" placeholder="Email" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="password" name="password" placeholder="Password" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <div class="mb-4">
      <label><input type="radio" name="role" value="listener" checked> Listener</label><br>
      <label><input type="radio" name="role" value="creator"> Creator</label>
    </div>
    <button type="submit" class="w-full bg-green-500 p-3 rounded font-bold">Register</button>
  </form>
  <p class="mt-4 text-center"><a href="/login" class="text-green-400">Already have an account?</a></p>
</div>
</body></html>`,

  login: `<!DOCTYPE html>
<html><head><title>Login - Tisaundike</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
<div class="bg-gray-800 p-8 rounded-lg w-full max-w-md">
  <h1 class="text-2xl font-bold mb-6 text-green-500">Login</h1>
  <% if (error) { %><p class="text-red-400 mb-4"><%= error %></p><% } %>
  <form method="POST">
    <input type="email" name="email" placeholder="Email" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="password" name="password" placeholder="Password" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <button type="submit" class="w-full bg-green-500 p-3 rounded font-bold">Login</button>
  </form>
  <p class="mt-4 text-center"><a href="/register" class="text-green-400">Create an account</a></p>
</div>
</body></html>`,

  'creator-dashboard': `<!DOCTYPE html>
<html><head><title>Creator Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen">
<nav class="bg-black p-4"><h1 class="text-xl font-bold text-green-500">Tisaundike Creator</h1></nav>
<div class="container mx-auto p-6">
  <h2 class="text-2xl font-bold mb-4">Welcome, <%= user.name %>!</h2>
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
    <div class="bg-gray-800 p-6 rounded"><h3 class="text-lg">Total Streams</h3><p class="text-3xl font-bold text-green-500"><%= totalStreams %></p></div>
    <div class="bg-gray-800 p-6 rounded"><h3 class="text-lg">Earnings</h3><p class="text-3xl font-bold text-green-500">$<%= earnings.toFixed(2) %></p></div>
    <div class="bg-gray-800 p-6 rounded"><a href="/upload" class="block text-center bg-green-500 p-3 rounded font-bold">Upload New Track</a></div>
  </div>
  <h3 class="text-xl mb-4">Your Tracks</h3>
  <div class="space-y-4">
    <% tracks.forEach(t => { %>
      <div class="bg-gray-800 p-4 rounded flex justify-between items-center">
        <div>
          <p class="font-bold"><%= t.title %></p>
          <p class="text-sm text-gray-400"><%= t.streams %> streams • $<%= (t.streams * 0.004).toFixed(2) %></p>
        </div>
        <a href="/stream/<%= t.id %>" class="text-green-400">Play</a>
      </div>
    <% }) %>
  </div>
</div>
</body></html>`,

  'listener-dashboard': `<!DOCTYPE html>
<html><head><title>Listener Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen">
<nav class="bg-black p-4"><h1 class="text-xl font-bold text-green-500">Tisaundike</h1></nav>
<div class="container mx-auto p-6">
  <h2 class="text-2xl font-bold mb-6">Your Playlists</h2>
  <% if (playlists.length === 0) { %>
    <p>No playlists yet. <a href="/" class="text-green-500">Discover music →</a></p>
  <% } else { %>
    <% playlists.forEach(p => { %>
      <div class="bg-gray-800 p-4 rounded mb-4">
        <h3 class="font-bold"><%= p.name %></h3>
        <p class="text-sm text-gray-400"><%= p.trackIds.split(',').length %> tracks</p>
      </div>
    <% }) %>
  <% } %>
</div>
</body></html>`,

  upload: `<!DOCTYPE html>
// tisaundike.js - Full Music Streaming Platform in ONE FILE
// Run: node tisaundike.js
// Visit: http://localhost:3000

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

// Ensure directories exist
const dirs = ['uploads/audio', 'uploads/covers', 'public'];
dirs.forEach(dir => !fs.existsSync(dir) && fs.mkdirSync(dir, { recursive: true }));

// Database
const db = new sqlite3.Database('tisaundike.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT,
    verified INTEGER DEFAULT 0,
    earnings REAL DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tracks (
    id TEXT PRIMARY KEY,
    title TEXT,
    artist TEXT,
    creatorId TEXT,
    genre TEXT,
    filePath TEXT,
    coverPath TEXT,
    streams INTEGER DEFAULT 0,
    uploadedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(creatorId) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS playlists (
    id TEXT PRIMARY KEY,
    name TEXT,
    userId TEXT,
    trackIds TEXT,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'tisaundike-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, file.fieldname.includes('audio') ? 'uploads/audio' : 'uploads/covers');
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Auth Middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  next();
};
const requireCreator = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'creator') {
    return res.status(403).send('Creators only');
  }
  next();
};

// Routes

// Home
app.get('/', async (req, res) => {
  const tracks = await new Promise((resolve) => {
    db.all('SELECT * FROM tracks ORDER BY streams DESC LIMIT 12', (err, rows) => resolve(rows || []));
  });
  res.render('index', { user: req.session.user, tracks });
});

// Register
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!['listener', 'creator'].includes(role)) return res.status(400).send('Invalid role');

  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (row) return res.render('register', { error: 'Email already exists' });

    db.run('INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
      [id, name, email, hashed, role], (err) => {
        if (err) return res.status(500).send('DB Error');
        res.redirect('/login');
      });
  });
});

// Login
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.redirect('/');
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
  const { user } = req.session;
  if (user.role === 'creator') {
    const tracks = await new Promise(resolve => {
      db.all('SELECT * FROM tracks WHERE creatorId = ?', [user.id], (err, rows) => resolve(rows));
    });
    const totalStreams = tracks.reduce((sum, t) => sum + t.streams, 0);
    const earnings = totalStreams * 0.004; // $0.004 per stream
    res.render('creator-dashboard', { user, tracks, totalStreams, earnings });
  } else {
    const playlists = await new Promise(resolve => {
      db.all('SELECT * FROM playlists WHERE userId = ?', [user.id], (err, rows) => resolve(rows));
    });
    res.render('listener-dashboard', { user, playlists });
  }
});

// Upload Track (Creator Only)
app.get('/upload', requireAuth, requireCreator, (req, res) => res.render('upload', { error: null }));
app.post('/upload', requireAuth, requireCreator, upload.fields([
  { name: 'audio', maxCount: 1 },
  { name: 'cover', maxCount: 1 }
]), (req, res) => {
  const { title, genre } = req.body;
  const audioFile = req.files['audio'][0];
  const coverFile = req.files['cover'][0];
  const creatorId = req.session.user.id;

  if (!audioFile || !title) return res.render('upload', { error: 'Audio & title required' });

  const trackId = uuidv4();
  db.run(`INSERT INTO tracks (id, title, artist, creatorId, genre, filePath, coverPath)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [trackId, title, req.session.user.name, creatorId, genre || 'Unknown',
     `/uploads/audio/${audioFile.filename}`, `/uploads/covers/${coverFile.filename}`],
    (err) => {
      if (err) return res.status(500).send('Upload failed');
      res.redirect('/dashboard');
    });
});

// Stream Track
app.get('/stream/:id', async (req, res) => {
  const track = await new Promise(resolve => {
    db.get('SELECT * FROM tracks WHERE id = ?', [req.params.id], (err, row) => resolve(row));
  });
  if (!track) return res.status(404).send('Track not found');

  // Increment stream count
  db.run('UPDATE tracks SET streams = streams + 1 WHERE id = ?', [track.id]);

  // Update creator earnings
  db.run('UPDATE users SET earnings = earnings + 0.004 WHERE id = ?', [track.creatorId]);

  res.render('player', { track, user: req.session.user });
});

// Search
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  const tracks = await new Promise(resolve => {
    db.all(`SELECT * FROM tracks WHERE title LIKE ? OR artist LIKE ?`,
      [`%${q}%`, `%${q}%`], (err, rows) => resolve(rows || []));
  });
  res.render('search', { tracks, query: q, user: req.session.user });
});

// Create Playlist
app.post('/playlist', requireAuth, (req, res) => {
  const { name, trackIds } = req.body;
  const id = uuidv4();
  db.run('INSERT INTO playlists (id, name, userId, trackIds) VALUES (?, ?, ?, ?)',
    [id, name, req.session.user.id, trackIds.join(',')], () => {
      res.redirect('/dashboard');
    });
});

// EJS Templates (Embedded as strings)
const templates = {
  index: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Tisaundike - Stream Music</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <style>body{font-family:'Inter',sans-serif;background:#121212;color:#fff;}</style>
</head>
<body class="min-h-screen">
  <nav class="bg-black p-4 flex justify-between items-center">
    <h1 class="text-2xl font-bold text-green-500">Tisaundike</h1>
    <div>
      <% if (!user) { %>
        <a href="/login" class="text-white mr-4">Login</a>
        <a href="/register" class="bg-green-500 px-4 py-2 rounded text-black">Sign Up</a>
      <% } else { %>
        <a href="/dashboard" class="text-white mr-4"><%= user.name %></a>
        <a href="/logout" class="text-red-400">Logout</a>
      <% } %>
    </div>
  </nav>

  <div class="container mx-auto p-6">
    <h2 class="text-3xl font-bold mb-6">Top Tracks</h2>
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">
      <% tracks.forEach(t => { %>
        <div class="bg-gray-900 p-4 rounded-lg hover:bg-gray-800 transition">
          <img src="<%= t.coverPath %>" alt="cover" class="w-full h-40 object-cover rounded mb-3">
          <h3 class="font-bold"><%= t.title %></h3>
          <p class="text-sm text-gray-400"><%= t.artist %> • <%= t.streams %> streams</p>
          <a href="/stream/<%= t.id %>" class="text-green-500 text-sm mt-2 inline-block">Play →</a>
        </div>
      <% }) %>
    </div>
  </div>
</body>
</html>`,

  register: `<!DOCTYPE html>
<html><head><title>Register - Tisaundike</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
<div class="bg-gray-800 p-8 rounded-lg w-full max-w-md">
  <h1 class="text-2xl font-bold mb-6 text-green-500">Create Account</h1>
  <% if (error) { %><p class="text-red-400 mb-4"><%= error %></p><% } %>
  <form method="POST">
    <input type="text" name="name" placeholder="Full Name" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="email" name="email" placeholder="Email" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="password" name="password" placeholder="Password" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <div class="mb-4">
      <label><input type="radio" name="role" value="listener" checked> Listener</label><br>
      <label><input type="radio" name="role" value="creator"> Creator</label>
    </div>
    <button type="submit" class="w-full bg-green-500 p-3 rounded font-bold">Register</button>
  </form>
  <p class="mt-4 text-center"><a href="/login" class="text-green-400">Already have an account?</a></p>
</div>
</body></html>`,

  login: `<!DOCTYPE html>
<html><head><title>Login - Tisaundike</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
<div class="bg-gray-800 p-8 rounded-lg w-full max-w-md">
  <h1 class="text-2xl font-bold mb-6 text-green-500">Login</h1>
  <% if (error) { %><p class="text-red-400 mb-4"><%= error %></p><% } %>
  <form method="POST">
    <input type="email" name="email" placeholder="Email" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="password" name="password" placeholder="Password" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <button type="submit" class="w-full bg-green-500 p-3 rounded font-bold">Login</button>
  </form>
  <p class="mt-4 text-center"><a href="/register" class="text-green-400">Create an account</a></p>
</div>
</body></html>`,

  'creator-dashboard': `<!DOCTYPE html>
<html><head><title>Creator Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen">
<nav class="bg-black p-4"><h1 class="text-xl font-bold text-green-500">Tisaundike Creator</h1></nav>
<div class="container mx-auto p-6">
  <h2 class="text-2xl font-bold mb-4">Welcome, <%= user.name %>!</h2>
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
    <div class="bg-gray-800 p-6 rounded"><h3 class="text-lg">Total Streams</h3><p class="text-3xl font-bold text-green-500"><%= totalStreams %></p></div>
    <div class="bg-gray-800 p-6 rounded"><h3 class="text-lg">Earnings</h3><p class="text-3xl font-bold text-green-500">$<%= earnings.toFixed(2) %></p></div>
    <div class="bg-gray-800 p-6 rounded"><a href="/upload" class="block text-center bg-green-500 p-3 rounded font-bold">Upload New Track</a></div>
  </div>
  <h3 class="text-xl mb-4">Your Tracks</h3>
  <div class="space-y-4">
    <% tracks.forEach(t => { %>
      <div class="bg-gray-800 p-4 rounded flex justify-between items-center">
        <div>
          <p class="font-bold"><%= t.title %></p>
          <p class="text-sm text-gray-400"><%= t.streams %> streams • $<%= (t.streams * 0.004).toFixed(2) %></p>
        </div>
        <a href="/stream/<%= t.id %>" class="text-green-400">Play</a>
      </div>
    <% }) %>
  </div>
</div>
</body></html>`,

  'listener-dashboard': `<!DOCTYPE html>
<html><head><title>Listener Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen">
<nav class="bg-black p-4"><h1 class="text-xl font-bold text-green-500">Tisaundike</h1></nav>
<div class="container mx-auto p-6">
  <h2 class="text-2xl font-bold mb-6">Your Playlists</h2>
  <% if (playlists.length === 0) { %>
    <p>No playlists yet. <a href="/" class="text-green-500">Discover music →</a></p>
  <% } else { %>
    <% playlists.forEach(p => { %>
      <div class="bg-gray-800 p-4 rounded mb-4">
        <h3 class="font-bold"><%= p.name %></h3>
        <p class="text-sm text-gray-400"><%= p.trackIds.split(',').length %> tracks</p>
      </div>
    <% }) %>
  <% } %>
</div>
</body></html>`,

  upload: `<!DOCTYPE html>
<html><head><title>Upload Track</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
<div class="bg-gray-800 p-8 rounded-lg w-full max-w-lg">
  <h1 class="text-2xl font-bold mb-6 text-green-500">Upload Music</h1>
  <% if (error) { %><p class="text-red-400 mb-4"><%= error %></p><% } %>
  <form method="POST" enctype="multipart/form-data">
    <input type="text" name="title" placeholder="Track Title" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="text" name="genre" placeholder="Genre (Optional)" class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="file" name="audio" accept="audio/*" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="file" name="cover" accept="image/*" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <button type="submit" class="w-full bg-green-500 p-3 rounded font-bold">Upload Track</button>
  </form>
</div>
</body></html>`,

  player: `<!DOCTYPE html>
<html><head><title>Now Playing</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-black text-white min-h-screen flex flex-col items-center justify-center">
  <div class="max-w-md w-full p-6 bg-gray-900 rounded-lg shadow-lg">
    <img src="<%= track.coverPath %>" alt="cover" class="w-full h-64 object-cover rounded mb-6">
    <h1 class="text-2xl font-bold"><%= track.title %></h1>
    <p class="text-lg text-gray-400"><%= track.artist %></p>
    <audio controls autoplay class="w-full mt-6">
      <source src="<%= track.filePath %>" type="audio/mpeg">
      Your browser does not support audio.
    </audio>
    <p class="text-sm text-gray-500 mt-4"><%= track.streams %> streams</p>
    <a href="/" class="mt-6 block text-center text-green-500">Back to Home</a>
  </div>
</body></html>`,

  search: `<!DOCTYPE html>
<html><head><title>Search</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen">
<nav class="bg-black p-4"><h1 class="text-xl font-bold text-green-500">Tisaundike</h1></nav>
<div class="container mx-auto p-6">
  <form method="GET" class="mb-6">
    <input type="text" name="q" value="<%= query %>" placeholder="Search songs, artists..." class="w-full p-3 bg-gray-800 rounded">
  </form>
  <% if (tracks.length === 0) { %>
    <p>No results for "<%= query %>"</p>
  <% } else { %>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <% tracks.forEach(t => { %>
        <div class="bg-gray-800 p-4 rounded">
          <h3 class="font-bold"><%= t.title %></h3>
          <p class="text-sm text-gray-400"><%= t.artist %></p>
          <a href="/stream/<%= t.id %>" class="text-green-500 text-sm">Play →</a>
        </div>
      <% }) %>
    </div>
  <% } %>
</div>
</body></html>`
};

// Render EJS from string
app.engine('ejs', require('ejs').renderFile);
app.set('views', __dirname);
for (const [name, template] of Object.entries(templates)) {
  const filePath = path.join(__dirname, `${name}.ejs`);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, template);
  }
  app.get(`/${name === 'index' ? '' : name}`, (req, res, next) => {
    if (name === 'index' && req.path !== '/') return next();
    res.render(`${name}.ejs`, res.locals);
  });
}

// Start Server
app.listen(PORT, () => {
  console.log(`Tisaundike is live at http://localhost:${PORT}`);
  console.log(`Upload audio to /upload (creators only)`);
});￼Enter  db.run('UPDATE tracks SET streams = streams + 1 WHERE id = ?', [track.id]);

  // Update creator earnings
  db.run('UPDATE users SET earnings = earnings + 0.004 WHERE id = ?', [track.creatorId]);

  res.render('player', { track, user: req.session.user });
});

// Search
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  const tracks = await new Promise(resolve => {
    db.all(`SELECT * FROM tracks WHERE title LIKE ? OR artist LIKE ?`,
      [`%${q}%`, `%${q}%`], (err, rows) => resolve(rows || []));
  });
  res.render('search', { tracks, query: q, user: req.session.user });
});

// Create Playlist
app.post('/playlist', requireAuth, (req, res) => {
  const { name, trackIds } = req.body;
  const id = uuidv4();
  db.run('INSERT INTO playlists (id, name, userId, trackIds) VALUES (?, ?, ?, ?)',
    [id, name, req.session.user.id, trackIds.join(',')], () => {
      res.redirect('/dashboard');
    });
});

// EJS Templates (Embedded as strings)
const templates = {
  index: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Tisaundike - Stream Music</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <style>body{font-family:'Inter',sans-serif;background:#121212;color:#fff;}</style>
</head>
<body class="min-h-screen">
  <nav class="bg-black p-4 flex justify-between items-center">
    <h1 class="text-2xl font-bold text-green-500">Tisaundike</h1>
    <div>
      <% if (!user) { %>
        <a href="/login" class="text-white mr-4">Login</a>
        <a href="/register" class="bg-green-500 px-4 py-2 rounded text-black">Sign Up</a>
      <% } else { %>
        <a href="/dashboard" class="text-white mr-4"><%= user.name %></a>
        <a href="/logout" class="text-red-400">Logout</a>
      <% } %>
    </div>
  </nav>

  <div class="container mx-auto p-6">
    <h2 class="text-3xl font-bold mb-6">Top Tracks</h2>
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">
      <% tracks.forEach(t => { %>
        <div class="bg-gray-900 p-4 rounded-lg hover:bg-gray-800 transition">
          <img src="<%= t.coverPath %>" alt="cover" class="w-full h-40 object-cover rounded mb-3">
          <h3 class="font-bold"><%= t.title %></h3>
          <p class="text-sm text-gray-400"><%= t.artist %> • <%= t.streams %> streams</p>
          <a href="/stream/<%= t.id %>" class="text-green-500 text-sm mt-2 inline-block">Play →</a>
        </div>
      <% }) %>
    </div>
  </div>
</body>
</html>`,

  register: `<!DOCTYPE html>
<html><head><title>Register - Tisaundike</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
<div class="bg-gray-800 p-8 rounded-lg w-full max-w-md">
  <h1 class="text-2xl font-bold mb-6 text-green-500">Create Account</h1>
  <% if (error) { %><p class="text-red-400 mb-4"><%= error %></p><% } %>
  <form method="POST">
nput type="text" name="name" placeholder="Full Name" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="email" name="email" placeholder="Email" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="password" name="password" placeholder="Password" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <div class="mb-4">
      <label><input type="radio" name="role" value="listener" checked> Listener</label><br>
      <label><input type="radio" name="role" value="creator"> Creator</label>
    </div>
    <button type="submit" class="w-full bg-green-500 p-3 rounded font-bold">Register</button>
  </form>
  <p class="mt-4 text-center"><a href="/login" class="text-green-400">Already have an account?</a></p>
</div>
</body></html>`,

  login: `<!DOCTYPE html>
<html><head><title>Login - Tisaundike</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
<div class="bg-gray-800 p-8 rounded-lg w-full max-w-md">
  <h1 class="text-2xl font-bold mb-6 text-green-500">Login</h1>
  <% if (error) { %><p class="text-red-400 mb-4"><%= error %></p><% } %>
  <form method="POST">
    <input type="email" name="email" placeholder="Email" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <input type="password" name="password" placeholder="Password" required class="w-full p-3 mb-4 bg-gray-700 rounded">
    <button type="submit" class="w-full bg-green-500 p-3 rounded font-bold">Login</button>
  </form>
  <p class="mt-4 text-center"><a href="/register" class="text-green-400">Create an account</a></p>
</div>
</body></html>`,

  'creator-dashboard': `<!DOCTYPE html>
<html><head><title>Creator Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen">
<nav class="bg-black p-4"><h1 class="text-xl font-bold text-green-500">Tisaundike Creator</h1></nav>
<div class="container mx-auto p-6">
  <h2 class="text-2xl font-bold mb-4">Welcome, <%= user.name %>!</h2>
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
    <div class="bg-gray-800 p-6 rounded"><h3 class="text-lg">Total Streams</h3><p class="text-3xl font-bold text-green-500"><%= totalStreams %></p></div>
    <div class="bg-gray-800 p-6 rounded"><h3 class="text-lg">Earnings</h3><p class="text-3xl font-bold text-green-500">$<%= earnings.toFixed(2) %></p></div>
    <div class="bg-gray-800 p-6 rounded"><a href="/upload" class="block text-center bg-green-500 p-3 rounded font-bold">Upload New Track</a></div>
  </div>
  <h3 class="text-xl mb-4">Your Tracks</h3>
  <div class="space-y-4">
    <% tracks.forEach(t => { %>
      <div class="bg-gray-800 p-4 rounded flex justify-between items-center">
        <div>
          <p class="font-bold"><%= t.title %></p>
          <p class="text-sm text-gray-400"><%= t.streams %> streams • $<%= (t.streams * 0.004).toFixed(2) %></p>
        </div>
        <a href="/stream/<%= t.id %>" class="text-green-400">Play</a>
      </div>
    <% }) %>
  </div>
</div>
</body></html>`,

  'listener-dashboard': `<!DOCTYPE html>
<html><head><title>Listener Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white min-h-screen">
<nav class="bg-black p-4"><h1 class="text-xl font-bold text-green-500">Tisaundike</h1></nav>
<div class="container mx-auto p-6">
  <h2 class="text-2xl font-bold mb-6">Your Playlists</h2>
  <% if (playlists.length === 0) { %>
    <p>No playlists yet. <a href="/" class="text-green-500">Discover music →</a></p>
  <% } else { %>
    <% playlists.forEach(p => { %>
      <div class="bg-gray-800 p-4 rounded mb-4">
        <h3 class="font-bold"><%= p.name %></h3>
        <p class="text-sm text-gray-400"><%= p.trackIds.split(',').length %> tracks</p>
      </div>
    <% }) %>
  <% } %>
</div>
</body></html>`,

  upload: `<!DOCTYPE html>
