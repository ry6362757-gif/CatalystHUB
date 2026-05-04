require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
app.use(cors());
app.use(express.json());

// ---------- Database Setup ----------
const db = new Database(process.env.DB_PATH || './eduboard.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('student','teacher')) NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS materials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    subject TEXT NOT NULL,
    chapter TEXT,
    content TEXT,
    file_url TEXT,
    uploaded_by_name TEXT,
    teacher_id INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (teacher_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    subject TEXT NOT NULL,
    chapter TEXT,
    questions TEXT NOT NULL,
    teacher_id INTEGER,
    created_by_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (teacher_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    test_id INTEGER,
    score INTEGER,
    total INTEGER,
    percentage INTEGER,
    taken_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (test_id) REFERENCES tests(id)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    for_role TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    is_read INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS teacher_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    teacher_id INTEGER NOT NULL,
    status TEXT CHECK(status IN ('pending','accepted','rejected')) DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (teacher_id) REFERENCES users(id),
    UNIQUE(student_id, teacher_id)
  );
`);

// ---------- Middleware ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ error: 'Access denied' });
    next();
  };
}

// ---------- Auth Routes (unchanged) ----------
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ error: 'All fields required' });
    if (!['student', 'teacher'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
                     .run(name, email, hashedPassword, role);
    const user = db.prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role },
                           process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role },
                           process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, created_at: user.created_at } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// ---------- Materials (visibility restricted) ----------
app.get('/api/materials', authenticateToken, (req, res) => {
  if (req.user.role === 'teacher') {
    // Teachers see only their own materials
    const materials = db.prepare('SELECT * FROM materials WHERE teacher_id = ? ORDER BY created_at DESC').all(req.user.id);
    return res.json(materials);
  }
  // Student: only materials from accepted teachers
  const acceptedTeachers = db.prepare('SELECT teacher_id FROM teacher_requests WHERE student_id = ? AND status = ?').all(req.user.id, 'accepted');
  if (acceptedTeachers.length === 0) return res.json([]);
  const teacherIds = acceptedTeachers.map(r => r.teacher_id);
  const placeholders = teacherIds.map(() => '?').join(',');
  const materials = db.prepare(`SELECT * FROM materials WHERE teacher_id IN (${placeholders}) ORDER BY created_at DESC`).all(...teacherIds);
  res.json(materials);
});

app.post('/api/materials', authenticateToken, requireRole('teacher'), (req, res) => {
  const { title, subject, chapter, content, file_url } = req.body;
  if (!title || !subject) return res.status(400).json({ error: 'Title and subject required' });
  const result = db.prepare('INSERT INTO materials (title, subject, chapter, content, file_url, uploaded_by_name, teacher_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
                  .run(title, subject, chapter, content || '', file_url || null, req.user.name, req.user.id);
  // Notify only connected students (accept them real‑time visibility)
  const connectedStudents = db.prepare('SELECT student_id FROM teacher_requests WHERE teacher_id = ? AND status = ?').all(req.user.id, 'accepted');
  if (connectedStudents.length > 0) {
    db.prepare('INSERT INTO notifications (message, for_role) VALUES (?, ?)').run(`New material from ${req.user.name}: ${title} (${subject})`, 'student');
  }
  const material = db.prepare('SELECT * FROM materials WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(material);
});

app.delete('/api/materials/:id', authenticateToken, requireRole('teacher'), (req, res) => {
  const material = db.prepare('SELECT * FROM materials WHERE id = ? AND teacher_id = ?').get(req.params.id, req.user.id);
  if (!material) return res.status(404).json({ error: 'Not found or not authorized' });
  db.prepare('DELETE FROM materials WHERE id = ?').run(req.params.id);
  res.json({ message: 'Deleted' });
});

// ---------- Tests (visibility restricted) ----------
app.get('/api/tests', authenticateToken, (req, res) => {
  if (req.user.role === 'teacher') {
    const tests = db.prepare('SELECT * FROM tests WHERE teacher_id = ? ORDER BY created_at DESC').all(req.user.id);
    return res.json(tests.map(t => ({ ...t, questions: JSON.parse(t.questions) })));
  }
  // Student: only tests from accepted teachers
  const acceptedTeachers = db.prepare('SELECT teacher_id FROM teacher_requests WHERE student_id = ? AND status = ?').all(req.user.id, 'accepted');
  if (acceptedTeachers.length === 0) return res.json([]);
  const teacherIds = acceptedTeachers.map(r => r.teacher_id);
  const placeholders = teacherIds.map(() => '?').join(',');
  const tests = db.prepare(`SELECT * FROM tests WHERE teacher_id IN (${placeholders}) ORDER BY created_at DESC`).all(...teacherIds);
  res.json(tests.map(t => ({ ...t, questions: JSON.parse(t.questions) })));
});

app.post('/api/tests', authenticateToken, requireRole('teacher'), (req, res) => {
  const { title, subject, chapter, questions } = req.body;
  if (!title || !subject || !questions) return res.status(400).json({ error: 'Missing fields' });
  const result = db.prepare('INSERT INTO tests (title, subject, chapter, questions, teacher_id, created_by_name) VALUES (?, ?, ?, ?, ?, ?)')
                  .run(title, subject, chapter, JSON.stringify(questions), req.user.id, req.user.name);
  const connectedStudents = db.prepare('SELECT student_id FROM teacher_requests WHERE teacher_id = ? AND status = ?').all(req.user.id, 'accepted');
  if (connectedStudents.length > 0) {
    db.prepare('INSERT INTO notifications (message, for_role) VALUES (?, ?)').run(`New test from ${req.user.name}: ${title} (${subject})`, 'student');
  }
  const test = db.prepare('SELECT * FROM tests WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ ...test, questions: JSON.parse(test.questions) });
});

app.delete('/api/tests/:id', authenticateToken, requireRole('teacher'), (req, res) => {
  const test = db.prepare('SELECT * FROM tests WHERE id = ? AND teacher_id = ?').get(req.params.id, req.user.id);
  if (!test) return res.status(404).json({ error: 'Not found or not authorized' });
  db.prepare('DELETE FROM tests WHERE id = ?').run(req.params.id);
  res.json({ message: 'Deleted' });
});

app.post('/api/tests/:testId/submit', authenticateToken, requireRole('student'), (req, res) => {
  const { score, total } = req.body;
  const testId = req.params.testId;
  const test = db.prepare('SELECT * FROM tests WHERE id = ?').get(testId);
  if (!test) return res.status(404).json({ error: 'Test not found' });
  // Only allow if student is connected to the test's teacher
  const connection = db.prepare('SELECT * FROM teacher_requests WHERE student_id = ? AND teacher_id = ? AND status = ?').get(req.user.id, test.teacher_id, 'accepted');
  if (!connection) return res.status(403).json({ error: 'Not connected to this teacher' });
  const percentage = Math.round((score / total) * 100);
  db.prepare('INSERT INTO progress (user_id, test_id, score, total, percentage) VALUES (?, ?, ?, ?, ?)').run(req.user.id, testId, score, total, percentage);
  res.status(201).json({ message: 'Submitted', score, total, percentage });
});

// ---------- Progress (teachers see only connected students) ----------
app.get('/api/progress', authenticateToken, (req, res) => {
  if (req.user.role === 'student') {
    const progress = db.prepare('SELECT * FROM progress WHERE user_id = ?').all(req.user.id);
    return res.json(progress);
  }
  if (req.user.role === 'teacher') {
    // Only progress of students who are connected to this teacher and have taken tests created by this teacher
    const connectedStudents = db.prepare('SELECT student_id FROM teacher_requests WHERE teacher_id = ? AND status = ?').all(req.user.id, 'accepted');
    if (connectedStudents.length === 0) return res.json([]);
    const studentIds = connectedStudents.map(r => r.student_id);
    const studentPlaceholders = studentIds.map(() => '?').join(',');
    const teacherTests = db.prepare('SELECT id FROM tests WHERE teacher_id = ?').all(req.user.id);
    const testIds = teacherTests.map(t => t.id);
    if (testIds.length === 0) return res.json([]);
    const testPlaceholders = testIds.map(() => '?').join(',');
    const progress = db.prepare(`
      SELECT p.*, u.name as student_name, u.email as student_email
      FROM progress p
      JOIN users u ON p.user_id = u.id
      WHERE p.user_id IN (${studentPlaceholders}) AND p.test_id IN (${testPlaceholders})
      ORDER BY p.taken_at DESC
    `).all(...studentIds, ...testIds);
    return res.json(progress);
  }
  res.json([]);
});

// ---------- Students list (connected only) ----------
app.get('/api/students', authenticateToken, requireRole('teacher'), (req, res) => {
  const students = db.prepare(`
    SELECT u.id, u.name, u.email
    FROM users u
    JOIN teacher_requests tr ON tr.student_id = u.id
    WHERE tr.teacher_id = ? AND tr.status = 'accepted'
    ORDER BY u.name
  `).all(req.user.id);
  res.json(students);
});

// ---------- Teacher list (for students to see all teachers) ----------
app.get('/api/teachers', authenticateToken, requireRole('student'), (req, res) => {
  const teachers = db.prepare('SELECT id, name, email FROM users WHERE role = ? ORDER BY name').all('teacher');
  res.json(teachers);
});

// ---------- Connection requests ----------
// Student sends request
app.post('/api/requests/send', authenticateToken, requireRole('student'), (req, res) => {
  const { teacherId } = req.body;
  if (!teacherId) return res.status(400).json({ error: 'teacherId required' });
  // Prevent duplicate
  const existing = db.prepare('SELECT * FROM teacher_requests WHERE student_id = ? AND teacher_id = ?').get(req.user.id, teacherId);
  if (existing) {
    if (existing.status === 'accepted') return res.status(409).json({ error: 'Already connected' });
    if (existing.status === 'pending') return res.status(409).json({ error: 'Request already sent' });
    // if rejected, allow re-request
    db.prepare('UPDATE teacher_requests SET status = ?, created_at = datetime("now") WHERE id = ?').run('pending', existing.id);
    return res.json({ message: 'Request sent again', requestId: existing.id });
  }
  const result = db.prepare('INSERT INTO teacher_requests (student_id, teacher_id) VALUES (?, ?)').run(req.user.id, teacherId);
  res.status(201).json({ message: 'Request sent', requestId: result.lastInsertRowid });
});

// Teacher gets pending requests
app.get('/api/requests/pending', authenticateToken, requireRole('teacher'), (req, res) => {
  const requests = db.prepare(`
    SELECT tr.id, tr.status, tr.created_at, u.id as student_id, u.name as student_name, u.email as student_email
    FROM teacher_requests tr
    JOIN users u ON tr.student_id = u.id
    WHERE tr.teacher_id = ? AND tr.status = 'pending'
    ORDER BY tr.created_at ASC
  `).all(req.user.id);
  res.json(requests);
});

// Teacher accepts request
app.put('/api/requests/:requestId/accept', authenticateToken, requireRole('teacher'), (req, res) => {
  const request = db.prepare('SELECT * FROM teacher_requests WHERE id = ? AND teacher_id = ?').get(req.params.requestId, req.user.id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') return res.status(400).json({ error: 'Request is not pending' });
  db.prepare('UPDATE teacher_requests SET status = ? WHERE id = ?').run('accepted', req.params.requestId);
  res.json({ message: 'Accepted' });
});

// Teacher rejects request
app.put('/api/requests/:requestId/reject', authenticateToken, requireRole('teacher'), (req, res) => {
  const request = db.prepare('SELECT * FROM teacher_requests WHERE id = ? AND teacher_id = ?').get(req.params.requestId, req.user.id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  db.prepare('UPDATE teacher_requests SET status = ? WHERE id = ?').run('rejected', req.params.requestId);
  res.json({ message: 'Rejected' });
});

// Student gets their requests (status with teacher name)
app.get('/api/requests/status', authenticateToken, requireRole('student'), (req, res) => {
  const requests = db.prepare(`
    SELECT tr.id, tr.status, tr.teacher_id, u.name as teacher_name, u.email as teacher_email, tr.created_at
    FROM teacher_requests tr
    JOIN users u ON tr.teacher_id = u.id
    WHERE tr.student_id = ?
    ORDER BY tr.created_at DESC
  `).all(req.user.id);
  res.json(requests);
});

// ---------- Notifications ----------
app.get('/api/notifications', authenticateToken, (req, res) => {
  const role = req.user.role;
  const notifs = db.prepare('SELECT * FROM notifications WHERE for_role = ? ORDER BY created_at DESC LIMIT 50').all(role);
  res.json(notifs);
});

app.put('/api/notifications/mark-read', authenticateToken, (req, res) => {
  const role = req.user.role;
  db.prepare('UPDATE notifications SET is_read = 1 WHERE for_role = ?').run(role);
  res.json({ message: 'Marked as read' });
});

// ---------- Start ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`EduBoard API running on port ${PORT}`));
