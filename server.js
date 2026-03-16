const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// SQLite Database setup
const db = new sqlite3.Database(':memory:');

// Create Users table
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, path TEXT, user_id INTEGER)");
});

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// User Registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, 'user'], (err) => {
        if (err) {
            return res.status(400).send(err.message);
        }
        res.status(201).send('User registered');
    });
});

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send('Invalid credentials');
        }
        const token = jwt.sign({ id: user.id, role: user.role }, 'YOUR_SECRET_KEY', { expiresIn: '1h' });
        res.json({ token });
    });
});

// Middleware for Admin Access
function checkAdmin(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(403);
    jwt.verify(token, 'YOUR_SECRET_KEY', (err, user) => {
        if (err || user.role !== 'admin') return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// File Upload
app.post('/upload', upload.single('file'), (req, res) => {
    const { user_id } = req.body; // Replace with actual user identification logic
    db.run("INSERT INTO files (filename, path, user_id) VALUES (?, ?, ?)", [req.file.originalname, req.file.path, user_id], (err) => {
        if (err) {
            return res.status(400).send(err.message);
        }
        res.status(201).send('File uploaded successfully');
    });
});

// File Download
app.get('/files/:id', (req, res) => {
    db.get("SELECT * FROM files WHERE id = ?", [req.params.id], (err, file) => {
        if (err || !file) {
            return res.status(404).send('File not found');
        }
        res.download(file.path);
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
