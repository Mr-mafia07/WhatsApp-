const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const pino = require('pino');
const chalk = require('chalk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

// 2. Initialization
const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const PORT = process.env.PORT || 20817;

// JWT Secret (should be in env in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Server start time for uptime tracking
const SERVER_START_TIME = Date.now();

// 3. Configuration Constants
// Reconnect config
const RECONNECT_MAX = 6;
const RECONNECT_DELAY_MS = 4000;

// Prune config
const MAX_PREKEY_FILES = parseInt(process.env.MAX_PREKEY_FILES || '20', 10);
const MAX_SENDER_KEY_FILES = parseInt(process.env.MAX_SENDER_KEY_FILES || '5', 10);
const MAX_SESSION_FILES = parseInt(process.env.MAX_SESSION_FILES || '10', 10);
const PRUNE_DEBOUNCE_MS = parseInt(process.env.PRUNE_DEBOUNCE_MS || '2000', 10);
const GLOBAL_PRUNE_INTERVAL_MS = parseInt(process.env.GLOBAL_PRUNE_INTERVAL_MS || (60 * 60 * 1000).toString(), 10);

// NEW: Resource limits and error thresholds
const SESSION_LIMITS = {
  maxReconnects: RECONNECT_MAX,
  maxConsecutiveSendErrors: 10,
  maxBadMacErrors: 5,
  maxOperationTimeout: 30000,
  cleanupVerificationTimeout: 5000
};

// 4. Directory Setup
const uploadsDir = path.join(process.cwd(), 'uploads');
const sessionsRoot = path.join(process.cwd(), 'uploaded_sessions');
const usersDataFile = path.join(process.cwd(), 'users.json');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(sessionsRoot)) fs.mkdirSync(sessionsRoot, { recursive: true });

// Initialize users file with default admin
if (!fs.existsSync(usersDataFile)) {
  const defaultAdmin = {
    username: 'admin',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin',
    createdAt: new Date().toISOString()
  };
  fs.writeFileSync(usersDataFile, JSON.stringify({ admin: defaultAdmin }, null, 2), 'utf8');
  console.log(chalk.green('✅ Default admin user created (username: admin, password: admin123)'));
}

// 5. Multer Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/\s+/g, ''))
});
const upload = multer({ storage });

// 6. Middleware Setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(process.cwd()));

// 7. In-Memory Data Structures
const SESSIONS = Object.create(null);
const CREDS_HASH_TO_SESSION = Object.create(null);
const DIR_WATCHERS = Object.create(null);

// NEW: Session-level error tracking
const SESSION_ERROR_COUNTERS = Object.create(null);

// ========================
// USER MANAGEMENT FUNCTIONS
// ========================

function loadUsers() {
  try {
    if (fs.existsSync(usersDataFile)) {
      const data = fs.readFileSync(usersDataFile, 'utf8');
      return JSON.parse(data);
    }
    return {};
  } catch (e) {
    logger.error('loadUsers error:', e?.message || e);
    return {};
  }
}

function saveUsers(users) {
  try {
    fs.writeFileSync(usersDataFile, JSON.stringify(users, null, 2), 'utf8');
    return true;
  } catch (e) {
    logger.error('saveUsers error:', e?.message || e);
    return false;
  }
}

function createUser(username, password, role = 'user') {
  const users = loadUsers();
  
  if (users[username]) {
    return { success: false, message: 'User already exists' };
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  users[username] = {
    username,
    password: hashedPassword,
    role,
    createdAt: new Date().toISOString()
  };

  if (saveUsers(users)) {
    return { success: true, message: 'User created successfully' };
  }

  return { success: false, message: 'Failed to save user' };
}

function verifyUser(username, password) {
  const users = loadUsers();
  const user = users[username];

  if (!user) {
    return { success: false, message: 'User not found' };
  }

  if (bcrypt.compareSync(password, user.password)) {
    return { success: true, user: { username: user.username, role: user.role } };
  }

  return { success: false, message: 'Invalid password' };
}

function generateToken(username, role) {
  // No expiry - token valid forever
  return jwt.sign({ username, role }, JWT_SECRET);
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// ========================
// AUTHENTICATION MIDDLEWARE
// ========================

function authMiddleware(req, res, next) {
  const token = req.cookies.authToken;

  if (!token) {
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ ok: false, error: 'Invalid token' });
  }

  req.user = decoded;
  next();
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ ok: false, error: 'Admin access required' });
  }
  next();
}

// 8. Utility Functions

function sha256File(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch (e) {
    logger.error({ filePath, err: e?.message }, 'sha256File failed');
    return null;
  }
}

function makeSessionId() {
  return 'sess_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9);
}

function makeSessionDir(sessionId) {
  const dir = path.join(sessionsRoot, sessionId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// NEW: Enhanced session error tracking
function initSessionErrorCounter(sessionId) {
  if (!SESSION_ERROR_COUNTERS[sessionId]) {
    SESSION_ERROR_COUNTERS[sessionId] = {
      badMacErrors: 0,
      consecutiveSendErrors: 0,
      reconnectAttempts: 0,
      totalErrors: 0,
      lastErrorTime: null
    };
  }
}

function incrementSessionError(sessionId, errorType) {
  initSessionErrorCounter(sessionId);
  const counter = SESSION_ERROR_COUNTERS[sessionId];

  if (errorType === 'badMac') counter.badMacErrors++;
  if (errorType === 'send') counter.consecutiveSendErrors++;
  if (errorType === 'reconnect') counter.reconnectAttempts++;

  counter.totalErrors++;
  counter.lastErrorTime = Date.now();
}

function resetSessionErrorCounter(sessionId, errorType) {
  if (!SESSION_ERROR_COUNTERS[sessionId]) return;
  const counter = SESSION_ERROR_COUNTERS[sessionId];

  if (errorType === 'send') counter.consecutiveSendErrors = 0;
  if (errorType === 'reconnect') counter.reconnectAttempts = 0;
  if (errorType === 'all') {
    counter.badMacErrors = 0;
    counter.consecutiveSendErrors = 0;
    counter.reconnectAttempts = 0;
  }
}

function clearSessionErrorCounter(sessionId) {
  delete SESSION_ERROR_COUNTERS[sessionId];
}

// NEW: Bad MAC error detection
function isBadMacError(error) {
  if (!error) return false;
  const msg = String(error?.message || error).toLowerCase();
  return msg.includes('bad-mac') ||
         msg.includes('bad mac') ||
         msg.includes('badmac') ||
         msg.includes('decryption error') ||
         msg.includes('mac verification failed');
}

// Enhanced logging with session isolation
function appendSessionLog(sessionId, rawMsg) {
  const time = new Date().toISOString();
  const msg = String(rawMsg || '');

  // Store log in memory for session (isolated per session)
  if (sessionId && SESSIONS[sessionId]) {
    const s = SESSIONS[sessionId];
    s.logs = s.logs || [];
    s.logs.push({ time, msg });
    if (s.logs.length > 1000) s.logs = s.logs.slice(-1000);
  }

  // Determine message classification
  const lower = msg.toLowerCase();
  let kind = 'other';

  if (/(sent|successful|success|reconnect successful|started|open|created|started loop)/.test(lower)) {
    kind = 'success';
  } else if (/(error|failed|deleted|logged out|invalid|unauthorized|401|disconnect|close|failed to)/.test(lower)) {
    kind = 'error';
  }

  // Console formatting
  const timeStr = chalk.yellow(`[${time}]`);
  let symbol = 'i';
  let symbolColored = chalk.cyan(`[${symbol}]`);
  let messageColored = chalk.cyan(msg);

  if (kind === 'success') {
    symbol = '✓';
    symbolColored = chalk.greenBright(`[${symbol}]`);
    messageColored = chalk.green(msg);
  } else if (kind === 'error') {
    symbol = '✗';
    symbolColored = chalk.redBright(`[${symbol}]`);
    messageColored = chalk.red(msg);
  }

  const sessionIdStr = sessionId ? chalk.magenta(`[${sessionId}]`) : '';
  const line = `${timeStr} ${symbolColored} ${messageColored} ${sessionIdStr}`;
  console.log(line);
  console.log(chalk.gray('─'.repeat(80)));

  // Structured logging
  logger.info({ sessionId, kind, time }, msg);
}

// NEW: Session-isolated error handler
async function handleSessionError(sessionId, error, context = '') {
  try {
    const errorMsg = error?.message || String(error);
    appendSessionLog(sessionId, `[${context}] Error: ${errorMsg}`);

    // Check for bad MAC error
    if (isBadMacError(error)) {
      appendSessionLog(sessionId, '🔴 Bad MAC error detected - attempting auto-recovery');
      incrementSessionError(sessionId, 'badMac');

      const counter = SESSION_ERROR_COUNTERS[sessionId];
      if (counter && counter.badMacErrors >= SESSION_LIMITS.maxBadMacErrors) {
        appendSessionLog(sessionId, `⚠️ Max bad MAC errors (${SESSION_LIMITS.maxBadMacErrors}) reached - stopping session`);
        await stopSessionCompletely(sessionId);
        return;
      }

      // Attempt to recover from bad MAC error
      await recoverFromBadMacError(sessionId);
    }

    // Log error but don't propagate to other sessions
    logger.error({ sessionId, context, error: errorMsg }, 'Session error (isolated)');
  } catch (e) {
    // Even error handling is isolated
    logger.error({ sessionId, err: e?.message }, 'Error in handleSessionError');
  }
}

// NEW: Bad MAC error recovery
async function recoverFromBadMacError(sessionId) {
  try {
    const s = SESSIONS[sessionId];
    if (!s || !s.sessionDir) return;

    appendSessionLog(sessionId, '🔧 Starting bad MAC recovery process...');

    // Close current socket
    try {
      if (s.sock) {
        if (s.sock.ws && typeof s.sock.ws.close === 'function') s.sock.ws.close();
        else if (s.sock.socket && typeof s.sock.socket.close === 'function') s.sock.socket.close();
        else if (typeof s.sock.end === 'function') s.sock.end();
      }
    } catch (e) {
      appendSessionLog(sessionId, 'Socket close error during recovery: ' + (e?.message || e));
    }

    // Delete problematic auth files but keep creds.json
    const PROTECTED_FILES = ['session.json', 'messages.txt', 'creds.json'];
    const sessionDir = s.sessionDir;

    try {
      const files = fs.readdirSync(sessionDir, { withFileTypes: true });
      let deletedCount = 0;

      for (const file of files) {
        if (file.isFile() && !PROTECTED_FILES.includes(file.name)) {
          try {
            fs.unlinkSync(path.join(sessionDir, file.name));
            deletedCount++;
          } catch (e) {
            logger.debug({ sessionId, file: file.name }, 'Failed to delete file during recovery');
          }
        }
      }

      // Delete keys directory
      const keysDir = path.join(sessionDir, 'keys');
      if (fs.existsSync(keysDir)) {
        fs.rmSync(keysDir, { recursive: true, force: true });
        appendSessionLog(sessionId, '✅ Deleted keys/ directory for recovery');
      }

      appendSessionLog(sessionId, `✅ Deleted ${deletedCount} auth files for recovery`);
    } catch (e) {
      appendSessionLog(sessionId, 'File cleanup error during recovery: ' + (e?.message || e));
    }

    // Wait before restart
    await sleep(2000);

    // Restart session with fresh auth
    appendSessionLog(sessionId, '🔄 Restarting session after bad MAC recovery...');
    await restartSession(sessionId);

  } catch (e) {
    appendSessionLog(sessionId, 'Bad MAC recovery failed: ' + (e?.message || e));
  }
}

function persistSessionFiles(sessionId) {
  // Wrap in try-catch for isolation
  try {
    const s = SESSIONS[sessionId];
    if (!s) return;

    const sessionMeta = {
      sessionId: s.sessionId,
      userId: s.userId,
      contacts: s.contacts,
      messages: s.messages,
      prefixName: s.prefixName,
      delayMs: s.delayMs,
      target: s.target,
      groupId: s.groupId,
      createdAt: s.createdAt || new Date().toISOString(),
      credsHash: s.credsHash || null
    };

    fs.writeFileSync(path.join(s.sessionDir, 'session.json'), JSON.stringify(sessionMeta, null, 2), 'utf8');
    fs.writeFileSync(path.join(s.sessionDir, 'messages.txt'), (s.messages || []).join('\n'), 'utf8');
  } catch (e) {
    // Log but don't crash other sessions
    appendSessionLog(sessionId, 'persistSessionFiles error: ' + (e?.message || e));
  }
}

function pruneAuthFiles(sessionDir, sessionId = null) {
  try {
    const PROTECTED_FILES = ['session.json', 'messages.txt', 'creds.json'];

    const patterns = [
      { regex: /^pre-?key.*\.json$/i, max: MAX_PREKEY_FILES, name: 'pre-key' },
      { regex: /^prekeys.*\.json$/i, max: MAX_PREKEY_FILES, name: 'prekeys' },
      { regex: /^signedprekey.*\.json$/i, max: MAX_PREKEY_FILES, name: 'signedprekey' },
      { regex: /^sender-key-.*\.json$/i, max: MAX_SENDER_KEY_FILES, name: 'sender-key' },
      { regex: /^session-[0-9]+.*\.json$/i, max: MAX_SESSION_FILES, name: 'session-numbered' },
      { regex: /^key-.*\.json$/i, max: MAX_PREKEY_FILES, name: 'key' }
    ];

    const files = fs.readdirSync(sessionDir, { withFileTypes: true })
      .filter(f => f.isFile())
      .map(f => f.name)
      .filter(fname => !PROTECTED_FILES.includes(fname));

    let totalRemoved = 0;
    const stats = {};

    for (const pattern of patterns) {
      let candidates = [];

      for (const fname of files) {
        if (pattern.regex.test(fname)) {
          const full = path.join(sessionDir, fname);
          let stat;
          try { stat = fs.statSync(full); } catch (e) { stat = null; }
          candidates.push({ name: fname, full, mtime: stat ? stat.mtimeMs : 0 });
        }
      }

      if (!candidates.length) continue;

      candidates.sort((a, b) => b.mtime - a.mtime);
      const toRemove = candidates.slice(pattern.max);

      if (!toRemove.length) continue;

      let removedCount = 0;
      for (const rem of toRemove) {
        try {
          fs.rmSync(rem.full, { force: true });
          removedCount++;
          logger.debug && logger.debug({ sessionDir, removed: rem.full }, `Pruned ${pattern.name} file`);
        } catch (e) {
          logger.debug && logger.debug({ sessionDir, err: (e?.message || e) }, `Failed to prune ${pattern.name} file`);
        }
      }

      if (removedCount > 0) {
        stats[pattern.name] = removedCount;
        totalRemoved += removedCount;
      }
    }

    // Prune keys subdirectory
    const keysDir = path.join(sessionDir, 'keys');
    if (fs.existsSync(keysDir) && fs.statSync(keysDir).isDirectory()) {
      const kfiles = fs.readdirSync(keysDir, { withFileTypes: true })
        .filter(f => f.isFile())
        .map(f => f.name);

      for (const pattern of patterns) {
        let candidates = [];

        for (const kf of kfiles) {
          if (pattern.regex.test(kf)) {
            const full = path.join(keysDir, kf);
            let stat;
            try { stat = fs.statSync(full); } catch (e) { stat = null; }
            candidates.push({ name: path.join('keys', kf), full, mtime: stat ? stat.mtimeMs : 0 });
          }
        }

        if (!candidates.length) continue;

        candidates.sort((a, b) => b.mtime - a.mtime);
        const toRemove = candidates.slice(pattern.max);

        if (!toRemove.length) continue;

        let removedCount = 0;
        for (const rem of toRemove) {
          try {
            fs.rmSync(rem.full, { force: true });
            removedCount++;
            logger.debug && logger.debug({ sessionDir, removed: rem.full }, `Pruned ${pattern.name} file from keys/`);
          } catch (e) {
            logger.debug && logger.debug({ sessionDir, err: (e?.message || e) }, `Failed to prune ${pattern.name} file from keys/`);
          }
        }

        if (removedCount > 0) {
          const key = `keys/${pattern.name}`;
          stats[key] = (stats[key] || 0) + removedCount;
          totalRemoved += removedCount;
        }
      }
    }

    if (totalRemoved > 0 && sessionId) {
      const summary = Object.entries(stats).map(([type, count]) => `${count} ${type}`).join(', ');
      appendSessionLog(sessionId, `🧹 Cleaned up: ${summary} files`);
    }

    return totalRemoved;
  } catch (e) {
    // Isolated error handling
    logger.debug && logger.debug({ sessionDir, err: (e?.message || e) }, 'pruneAuthFiles error');
    return 0;
  }
}

function startSessionWatch(sessionId) {
  try {
    const s = SESSIONS[sessionId];
    if (!s) return;
    const sessionDir = s.sessionDir;
    if (!sessionDir || !fs.existsSync(sessionDir)) return;

    if (DIR_WATCHERS[sessionId]) return;

    const watchers = { dirWatcher: null, keysWatcher: null, debounceTimer: null };

    const schedulePrune = () => {
      if (watchers.debounceTimer) clearTimeout(watchers.debounceTimer);
      watchers.debounceTimer = setTimeout(() => {
        try {
          const removed = pruneAuthFiles(sessionDir, sessionId);
          if (removed && removed > 0) {
            logger.debug && logger.debug({ sessionId, removed }, 'Pruned auth files after fs event');
          }
        } catch (e) {
          logger.debug && logger.debug({ sessionId, err: (e?.message || e) }, 'watch prune error');
        }
        watchers.debounceTimer = null;
      }, PRUNE_DEBOUNCE_MS);
    };

    try {
      watchers.dirWatcher = fs.watch(sessionDir, (eventType, filename) => {
        if (!filename) return;
        schedulePrune();
      });
    } catch (e) {
      logger.debug && logger.debug({ sessionId, err: e?.message || e }, 'Failed to set dir watcher');
    }

    try {
      const keysDir = path.join(sessionDir, 'keys');
      if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });
      watchers.keysWatcher = fs.watch(keysDir, (eventType, filename) => {
        if (!filename) return;
        schedulePrune();
      });
    } catch (e) {
      logger.debug && logger.debug({ sessionId, err: e?.message || e }, 'Failed to set keys watcher');
    }

    DIR_WATCHERS[sessionId] = watchers;
  } catch (e) {
    // Isolated error
    logger.error({ sessionId, err: e?.message }, 'startSessionWatch failed');
  }
}

// NEW: Enhanced stopSessionWatch with complete cleanup
function stopSessionWatch(sessionId) {
  try {
    const w = DIR_WATCHERS[sessionId];
    if (!w) return;

    // Close all watchers
    try {
      if (w.dirWatcher) {
        w.dirWatcher.close();
        w.dirWatcher = null;
      }
    } catch (e) {
      logger.debug({ sessionId }, 'Error closing dir watcher');
    }

    try {
      if (w.keysWatcher) {
        w.keysWatcher.close();
        w.keysWatcher = null;
      }
    } catch (e) {
      logger.debug({ sessionId }, 'Error closing keys watcher');
    }

    // Clear timers
    try {
      if (w.debounceTimer) {
        clearTimeout(w.debounceTimer);
        w.debounceTimer = null;
      }
    } catch (e) {
      logger.debug({ sessionId }, 'Error clearing debounce timer');
    }

    delete DIR_WATCHERS[sessionId];
    appendSessionLog(sessionId, '✅ All watchers and timers stopped');
  } catch (e) {
    logger.error({ sessionId, err: e?.message }, 'stopSessionWatch error');
  }
}

// UPDATED: Complete session folder deletion (no protected files)
async function cleanupSessionFiles(sessionId) {
  try {
    const s = SESSIONS[sessionId];
    if (!s || !s.sessionDir) {
      logger.info({ sessionId }, 'cleanupSessionFiles: session not found');
      return;
    }

    appendSessionLog(sessionId, '🗑️ Starting COMPLETE deletion of session folder...');

    // Delete the entire session folder including ALL files
    try {
      if (fs.existsSync(s.sessionDir)) {
        fs.rmSync(s.sessionDir, { recursive: true, force: true });
        appendSessionLog(sessionId, '✅ Complete session folder deleted from uploaded_sessions');
      } else {
        appendSessionLog(sessionId, '⚠️ Session folder already removed');
      }
    } catch (e) {
      appendSessionLog(sessionId, '❌ Folder deletion error: ' + (e?.message || e));
      logger.error({ sessionId, err: e?.message }, 'Failed to delete session folder');
    }

    // Verify deletion
    await sleep(500);
    if (!fs.existsSync(s.sessionDir)) {
      appendSessionLog(sessionId, '✅ Deletion verified: Session folder completely removed');
    } else {
      appendSessionLog(sessionId, '⚠️ Session folder still exists after deletion attempt');
    }
  } catch (e) {
    appendSessionLog(sessionId, '❌ Cleanup error: ' + (e?.message || e));
  }
}

// UPDATED: Complete session stop with full folder deletion
async function stopSessionCompletely(sessionId) {
  try {
    const s = SESSIONS[sessionId];
    if (!s) return;

    appendSessionLog(sessionId, '🛑 Initiating complete session stop and folder deletion...');

    // Mark as deleting to stop loops
    s.deleting = true;
    s.runningLoop = false;

    // 1. Close socket connection
    try {
      const sock = s.sock;
      if (sock) {
        if (sock.ws && typeof sock.ws.close === 'function') sock.ws.close();
        else if (sock.socket && typeof sock.socket.close === 'function') sock.socket.close();
        else if (typeof sock.end === 'function') sock.end();
        appendSessionLog(sessionId, '✅ Socket closed');
        s.sock = null;
      }
    } catch (e) {
      appendSessionLog(sessionId, 'Socket close error: ' + (e?.message || e));
    }

    // 2. Stop file watchers
    stopSessionWatch(sessionId);

    // 3. Delete complete session folder (including session.json, creds.json, message.txt, keys/)
    await cleanupSessionFiles(sessionId);

    // 4. Clear memory references
    try {
      if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash]) {
        delete CREDS_HASH_TO_SESSION[s.credsHash];
      }

      // Clear error counters
      clearSessionErrorCounter(sessionId);

      // Remove from sessions
      delete SESSIONS[sessionId];

      appendSessionLog(sessionId, '✅ All memory references cleared');
    } catch (e) {
      appendSessionLog(sessionId, 'Memory cleanup error: ' + (e?.message || e));
    }

    appendSessionLog(sessionId, '✅ Complete session stop and folder deletion finished');
  } catch (e) {
    logger.error({ sessionId, err: e?.message }, 'stopSessionCompletely error');
  }
}

function isLoggedOutUpdate(update) {
  const last = update?.lastDisconnect;
  if (!last) return false;
  const msg = (last.error && (last.error.message || String(last.error))) || String(last?.error || '');
  if (!msg) return false;
  const lower = msg.toLowerCase();
  return lower.includes('logged out') ||
         lower.includes('invalid') ||
         lower.includes('unauthorized') ||
         lower.includes('401') ||
         lower.includes('auth');
}

async function restartSession(sessionId) {
  try {
    const s = SESSIONS[sessionId];
    if (!s) {
      appendSessionLog(sessionId, 'restartSession: no in-memory session found');
      return;
    }

    const dir = s.sessionDir;
    if (!dir || !fs.existsSync(dir)) {
      appendSessionLog(sessionId, 'restartSession: session folder missing, cannot restart');
      return;
    }

    appendSessionLog(sessionId, '🔄 Restarting session from disk: ' + dir);

    // Reload metadata
    try {
      const sessionJsonPath = path.join(dir, 'session.json');
      if (fs.existsSync(sessionJsonPath)) {
        const meta = JSON.parse(fs.readFileSync(sessionJsonPath, 'utf8'));
        s.userId = meta.userId || s.userId;
        s.contacts = meta.contacts || s.contacts;
        s.messages = meta.messages || s.messages;
        s.prefixName = meta.prefixName || s.prefixName || 'Bot';
        s.delayMs = meta.delayMs || s.delayMs || 5000;
        s.target = meta.target || s.target;
        s.groupId = meta.groupId || s.groupId;
        s.createdAt = meta.createdAt || s.createdAt;
        s.credsHash = meta.credsHash || s.credsHash;
        if (s.credsHash) CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;
      }
    } catch (e) {
      appendSessionLog(sessionId, 'Failed to read session.json during restart: ' + (e?.message || e));
    }

    // Reset state
    s.runningLoop = false;
    s.deleting = false;
    resetSessionErrorCounter(sessionId, 'all');

    // Recreate socket
    try {
      s.sock = await createOrGetSocket(dir, sessionId);
    } catch (e) {
      await handleSessionError(sessionId, e, 'restartSession socket creation');
    }

    // Restart sending loop
    try {
      await startSendingLoop(sessionId, s.contacts, s.messages, s.prefixName, s.delayMs, s.target, s.groupId);
      appendSessionLog(sessionId, '✅ Session restarted and sending loop started');
    } catch (e) {
      await handleSessionError(sessionId, e, 'restartSession startSendingLoop');
    }
  } catch (e) {
    await handleSessionError(sessionId, e, 'restartSession');
  }
}

async function attemptReconnect(sessionId) {
  try {
    const s = SESSIONS[sessionId];
    if (!s) return;

    if (s.reconnectLock) {
      appendSessionLog(sessionId, 'Reconnect attempt already in progress, skipping duplicate call');
      return;
    }

    s.reconnectLock = true;

    for (let i = 0; i < RECONNECT_MAX; i++) {
      incrementSessionError(sessionId, 'reconnect');
      const attempt = i + 1;

      appendSessionLog(sessionId, `Reconnect attempt ${attempt}/${RECONNECT_MAX} (waiting ${RECONNECT_DELAY_MS}ms)`);
      await sleep(RECONNECT_DELAY_MS);

      if (!SESSIONS[sessionId]) {
        appendSessionLog(sessionId, 'Session removed during reconnect, aborting');
        s.reconnectLock = false;
        return;
      }

      try {
        const newSock = await createOrGetSocket(s.sessionDir, sessionId);
        if (newSock) {
          s.sock = newSock;
          appendSessionLog(sessionId, 'Reconnect: new socket created, waiting for open');

          try {
            await waitForSocketOpen(sessionId, 20000);
            appendSessionLog(sessionId, '✅ Reconnect successful');
            resetSessionErrorCounter(sessionId, 'reconnect');
            s.reconnectLock = false;
            return;
          } catch (e) {
            appendSessionLog(sessionId, 'Reconnect: socket not open yet: ' + (e?.message || e));
          }
        }
      } catch (e) {
        await handleSessionError(sessionId, e, 'attemptReconnect try');
      }
    }

    s.reconnectLock = false;
    appendSessionLog(sessionId, `Max reconnect attempts (${RECONNECT_MAX}) reached. Restarting session.`);

    try {
      await restartSession(sessionId);
    } catch (e) {
      await handleSessionError(sessionId, e, 'restartSession after max reconnects');
    }
  } catch (e) {
    await handleSessionError(sessionId, e, 'attemptReconnect');
  }
}

function restoreSessionsFromDisk() {
  try {
    const entries = fs.existsSync(sessionsRoot) ? fs.readdirSync(sessionsRoot, { withFileTypes: true }) : [];

    for (const e of entries) {
      if (!e.isDirectory()) continue;

      const sessionId = e.name;
      const dir = path.join(sessionsRoot, sessionId);
      const sessionJsonPath = path.join(dir, 'session.json');
      const credsPath = path.join(dir, 'creds.json');

      if (fs.existsSync(sessionJsonPath) && fs.existsSync(credsPath)) {
        try {
          const meta = JSON.parse(fs.readFileSync(sessionJsonPath, 'utf8'));

          const sess = {
            sessionId: meta.sessionId || sessionId,
            sessionDir: dir,
            userId: meta.userId || 'unknown',
            credsHash: meta.credsHash || null,
            contacts: meta.contacts || [],
            messages: meta.messages || [],
            prefixName: meta.prefixName || 'Bot',
            delayMs: meta.delayMs || 5000,
            runningLoop: false,
            sock: null,
            target: meta.target || 'contacts',
            groupId: meta.groupId || null,
            logs: [],
            createdAt: meta.createdAt || new Date().toISOString(),
            reconnectLock: false,
            deleting: false
          };

          SESSIONS[sess.sessionId] = sess;

          // Initialize error counter
          initSessionErrorCounter(sess.sessionId);

          // Calculate credsHash
          if (fs.existsSync(credsPath)) {
            try {
              const hash = sha256File(credsPath);
              if (hash) {
                sess.credsHash = hash;
                CREDS_HASH_TO_SESSION[hash] = sess.sessionId;
              }
            } catch (e) {
              logger.debug({ sessionId: sess.sessionId }, 'Failed to hash creds on restore');
            }
          }

          appendSessionLog(sess.sessionId, '📂 Restored session from disk, starting socket and loop');

          try {
            startSessionWatch(sess.sessionId);
          } catch (e) {
            logger.debug({ sessionId: sess.sessionId, err: e?.message || e }, 'start watch failed on restore');
          }

          // Async socket creation and loop start (isolated)
          (async () => {
            try {
              SESSIONS[sess.sessionId].sock = await createOrGetSocket(sess.sessionDir, sess.sessionId);
            } catch (e) {
              await handleSessionError(sess.sessionId, e, 'restore socket creation');
            }

            try {
              await startSendingLoop(sess.sessionId, sess.contacts, sess.messages, sess.prefixName, sess.delayMs, sess.target, sess.groupId);
            } catch (err) {
              await handleSessionError(sess.sessionId, err, 'restore startSendingLoop');
            }
          })();

        } catch (err) {
          logger.warn('Failed to restore session', sessionId, err?.message || err);
        }
      }
    }
  } catch (e) {
    logger.error({ err: e?.message }, 'restoreSessionsFromDisk failed');
  }
}

async function createOrGetSocket(sessionDir, sessionId) {
  let baileys;
  try {
    baileys = await import('@whiskeysockets/baileys');
  } catch (e) {
    logger.error('Please npm install @whiskeysockets/baileys', e?.message || e);
    throw e;
  }

  const {
    makeWASocket,
    useMultiFileAuthState,
    makeCacheableSignalKeyStore,
    Browsers,
    fetchLatestBaileysVersion
  } = baileys;

  // Ensure directories exist
  if (!fs.existsSync(sessionDir)) fs.mkdirSync(sessionDir, { recursive: true });
  const keysDir = path.join(sessionDir, 'keys');
  if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });

  let state, saveCreds;
  try {
    ({ state, saveCreds } = await useMultiFileAuthState(sessionDir));
  } catch (e) {
    appendSessionLog(sessionId, 'useMultiFileAuthState failed: ' + (e?.message || e));

    // Log session folder details for debugging
    try {
      const files = fs.readdirSync(sessionDir);
      appendSessionLog(sessionId, 'Session folder files: ' + files.join(', '));

      for (const fname of ['creds.json', 'session.json']) {
        const fp = path.join(sessionDir, fname);
        if (fs.existsSync(fp)) {
          try {
            const content = fs.readFileSync(fp, 'utf8');
            const preview = content.slice(0, 800).replace(/[\r\n]+/g, ' ');
            appendSessionLog(sessionId, `Preview of ${fname}: ${preview}`);
          } catch (re) {
            appendSessionLog(sessionId, `Failed to read ${fname}: ${re?.message || re}`);
          }
        }
      }
    } catch (ee) {
      appendSessionLog(sessionId, 'Failed listing session folder: ' + (ee?.message || ee));
    }

    throw e;
  }

  let version;
  try {
    ({ version } = await fetchLatestBaileysVersion());
  } catch (e) {
    logger.warn('fetchLatestBaileysVersion failed');
  }

  // Create socket
  const sock = makeWASocket({
    version,
    logger: pino({ level: 'silent' }),
    browser: Browsers.macOS('Safari'),
    auth: {
      creds: state.creds,
      keys: makeCacheableSignalKeyStore(state.keys, pino().child({ level: 'fatal' }))
    },
    markOnlineOnConnect: true,
    generateHighQualityLinkPreview: false,
  });

  // Credential update handler (isolated)
  if (sock?.ev?.on) {
    sock.ev.on('creds.update', async () => {
      try {
        if (typeof saveCreds === 'function') await saveCreds();
        fs.writeFileSync(path.join(sessionDir, 'creds.json'), JSON.stringify(state.creds || {}, null, 2), 'utf8');

        // Prune after creds update
        try {
          const removed = pruneAuthFiles(sessionDir, sessionId);
          if (removed && removed > 0) {
            logger.debug && logger.debug({ sessionId, removed }, 'Pruned auth files after creds.update');
          }
        } catch (e) {
          logger.debug && logger.debug({ sessionId, err: (e?.message || e) }, 'pruneAuthFiles failed in creds.update');
        }
      } catch (e) {
        await handleSessionError(sessionId, e, 'creds.update handler');
      }
    });
  }

  // Connection update handler (isolated with bad MAC detection)
  sock.ev.on('connection.update', async (update) => {
    try {
      const { connection } = update;

      if (connection === 'close') {
        const error = update?.lastDisconnect?.error;
        const errorMsg = error?.message || String(error || 'unknown');

        appendSessionLog(sessionId, 'Socket closed: ' + errorMsg);

        // Check for bad MAC error
        if (isBadMacError(error)) {
          appendSessionLog(sessionId, '🔴 Bad MAC error detected in connection close');
          await handleSessionError(sessionId, error, 'connection.update close');
          return;
        }

        // Check for logged out
        if (isLoggedOutUpdate(update)) {
          appendSessionLog(sessionId, '❌ Detected logged out/invalid creds. Stopping session.');
          try {
            await stopSessionCompletely(sessionId);
          } catch (e) {
            await handleSessionError(sessionId, e, 'logout cleanup');
          }
          return;
        }

        // Normal reconnect
        appendSessionLog(sessionId, 'Socket closed, starting reconnect attempts...');
        attemptReconnect(sessionId).catch(err => handleSessionError(sessionId, err, 'attemptReconnect'));
      }

      if (connection === 'open') {
        appendSessionLog(sessionId, '✅ Socket open');

        // Reset error counters on successful connection
        resetSessionErrorCounter(sessionId, 'all');

        try {
          startSessionWatch(sessionId);
        } catch (e) {
          logger.debug && logger.debug({ sessionId, err: e?.message || e }, 'start watch on open failed');
        }

        // Prune on successful connection
        try {
          const removed = pruneAuthFiles(sessionDir, sessionId);
          if (removed && removed > 0) {
            logger.debug && logger.debug({ sessionId, removed }, 'Pruned auth files on socket open');
          }
        } catch (e) {
          logger.debug && logger.debug({ sessionId, err: (e?.message || e) }, 'prune on open failed');
        }
      }
    } catch (e) {
      await handleSessionError(sessionId, e, 'connection.update handler');
    }
  });

  return sock;
}

async function waitForSocketOpen(sessionId, timeoutMs = 20000) {
  const s = SESSIONS[sessionId];
  if (!s || !s.sock) throw new Error('No session or socket');

  const sock = s.sock;
  if (sock?.authState?.creds?.registered || (sock.user && Object.keys(sock.user || {}).length)) return;

  return new Promise((resolve, reject) => {
    let done = false;
    const to = setTimeout(() => {
      if (!done) {
        done = true;
        reject(new Error('timeout'));
      }
    }, timeoutMs);

    const handler = (update) => {
      const { connection } = update;
      if (connection === 'open') {
        if (!done) {
          done = true;
          clearTimeout(to);
          sock.ev.off('connection.update', handler);
          resolve();
        }
      }
    };

    sock.ev.on('connection.update', handler);
  });
}

// Enhanced sending loop with better error handling
async function startSendingLoop(sessionId, contacts, messages, prefixName, delayMs, target, groupId) {
  try {
    const s = SESSIONS[sessionId];
    if (!s) throw new Error('Session not found');
    if (s.runningLoop) return;

    s.runningLoop = true;
    appendSessionLog(sessionId, '🚀 Started sending loop');

    let index = 0;

    while (SESSIONS[sessionId]) {
      try {
        // Check if session is being deleted
        if (s.deleting) {
          appendSessionLog(sessionId, 'Sending loop: session is deleting, exiting loop');
          break;
        }

        // Ensure socket exists
        if (!s.sock) {
          try {
            s.sock = await createOrGetSocket(s.sessionDir, sessionId);
          } catch (e) {
            await handleSessionError(sessionId, e, 'loop socket creation');
            await sleep(5000);
            continue;
          }
        }

        // Wait for socket to open
        try {
          await waitForSocketOpen(sessionId, 20000);
        } catch (e) {
          appendSessionLog(sessionId, 'Socket not open yet in loop');
        }

        const contact = (contacts && contacts.length) ? contacts[index % contacts.length] : null;
        const messageToSend = (messages && messages.length) ? messages[index % messages.length] : '';
        const fullMessage = (prefixName || 'Bot') + ' ' + messageToSend;

        try {
          const baileys = await import('@whiskeysockets/baileys');
          let jid;

          if (target === 'gc') {
            jid = (groupId + '@g.us');
          } else {
            jid = contact ? baileys.jidNormalizedUser(contact + '@s.whatsapp.net') : null;
          }

          if (!jid) throw new Error('Invalid JID');

          await s.sock.sendMessage(jid, { text: fullMessage });
          s.lastUsed = Date.now();

          // Reset error counter on successful send
          resetSessionErrorCounter(sessionId, 'send');

          appendSessionLog(sessionId, `✅ Message sent to ${jid}`);

        } catch (err) {
          // Check for bad MAC error in send
          if (isBadMacError(err)) {
            await handleSessionError(sessionId, err, 'send message');
            await sleep(5000);
            continue;
          }

          appendSessionLog(sessionId, '❌ Send failed: ' + String(err?.message || err));
          incrementSessionError(sessionId, 'send');

          const counter = SESSION_ERROR_COUNTERS[sessionId];
          if (counter && counter.consecutiveSendErrors >= SESSION_LIMITS.maxConsecutiveSendErrors) {
            appendSessionLog(sessionId, `⚠️ Reached ${SESSION_LIMITS.maxConsecutiveSendErrors} consecutive send failures. Restarting session.`);
            resetSessionErrorCounter(sessionId, 'send');

            try {
              await restartSession(sessionId);
            } catch (e) {
              await handleSessionError(sessionId, e, 'restart after send errors');
            }
          }
        }

        index++;
        persistSessionFiles(sessionId);
        await sleep(delayMs);

      } catch (e) {
        await handleSessionError(sessionId, e, 'sending loop iteration');
        await sleep(2000);
      }
    }

    if (SESSIONS[sessionId]) {
      SESSIONS[sessionId].runningLoop = false;
      appendSessionLog(sessionId, 'ℹ️ Sending loop stopped');
    }
  } catch (e) {
    await handleSessionError(sessionId, e, 'startSendingLoop');
  }
}

// ========================
// AUTHENTICATION API ENDPOINTS
// ========================

app.get('/', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'index.html'));
});

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ ok: false, error: 'Username and password required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ ok: false, error: 'Username must be at least 3 characters' });
    }

    if (password.length < 6) {
      return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters' });
    }

    const result = createUser(username, password, 'user');

    if (result.success) {
      return res.json({ ok: true, message: result.message });
    } else {
      return res.status(400).json({ ok: false, error: result.message });
    }
  } catch (e) {
    logger.error('signup error:', e?.message || e);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ ok: false, error: 'Username and password required' });
    }

    const result = verifyUser(username, password);

    if (result.success) {
      const token = generateToken(result.user.username, result.user.role);
      
      // Set cookie with no expiry
      res.cookie('authToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });

      return res.json({ 
        ok: true, 
        message: 'Login successful',
        user: result.user
      });
    } else {
      return res.status(401).json({ ok: false, error: result.message });
    }
  } catch (e) {
    logger.error('login error:', e?.message || e);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  res.clearCookie('authToken');
  res.json({ ok: true, message: 'Logged out successfully' });
});

// Verify token endpoint
app.get('/api/verify', authMiddleware, (req, res) => {
  res.json({ ok: true, user: { username: req.user.username, role: req.user.role } });
});

// Get uptime (public endpoint)
app.get('/api/uptime', (req, res) => {
  try {
    const uptimeMs = Date.now() - SERVER_START_TIME;
    const uptimeSeconds = Math.floor(uptimeMs / 1000);
    const days = Math.floor(uptimeSeconds / 86400);
    const hours = Math.floor((uptimeSeconds % 86400) / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;

    res.json({
      ok: true,
      uptimeMs,
      uptimeFormatted: `${days}d ${hours}h ${minutes}m ${seconds}s`,
      startTime: new Date(SERVER_START_TIME).toISOString(),
      activeSessions: Object.keys(SESSIONS).length
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// ========================
// SESSION API ENDPOINTS (Protected)
// ========================

app.post('/send-message', authMiddleware, upload.fields([
  { name: 'creds', maxCount: 1 },
  { name: 'messageFile', maxCount: 1 }
]), async (req, res) => {
  try {
    const userId = req.user.username;
    const files = req.files || {};
    const credsFileObj = (files.creds && files.creds[0]) || null;
    const messageFileObj = (files.messageFile && files.messageFile[0]) || null;
    const { name: prefixName, type, targetID, delayTime } = req.body || {};
    const delaySeconds = parseInt(delayTime || '5', 10) || 5;
    const delayMs = delaySeconds * 1000;

    if (!credsFileObj) return res.status(400).send('<div class=\"muted\">No creds.json uploaded</div>');
    if (!messageFileObj) return res.status(400).send('<div class=\"muted\">No message file uploaded</div>');
    if (!type || !targetID) return res.status(400).send('<div class=\"muted\">Missing type or targetID</div>');

    let contacts = [];
    if (type === 'gc') {
      contacts = [targetID.trim()];
    } else {
      const raw = String(targetID || '');
      const parts = raw.split(/[,\r\n]+/).map(x => x.trim()).filter(Boolean);
      contacts = parts.map(p => p.replace(/[^\d+]/g, '').replace(/^\+/, ''));
      if (!contacts.length) return res.status(400).send('<div class=\"muted\">No valid contact numbers provided</div>');
    }

    const txt = fs.readFileSync(messageFileObj.path, 'utf8');
    const lines = txt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const messages = lines.length ? lines : [txt.trim()];
    if (!messages.length || !messages[0]) return res.status(400).send('<div class=\"muted\">No message content</div>');

    // Check for duplicate creds
    const uploadedPath = credsFileObj.path;
    const credsHash = sha256File(uploadedPath);

    if (credsHash && CREDS_HASH_TO_SESSION[credsHash]) {
      try { fs.unlinkSync(uploadedPath); } catch (e) {}
      try { fs.unlinkSync(messageFileObj.path); } catch (e) {}
      res.status(409).set('Content-Type', 'text/html; charset=utf-8');
      return res.send('<div style=\"padding:10px\"><strong>Duplicate creds detected.</strong><div class=\"muted\">Only one active session is allowed per creds.json. Stop the existing session first to reuse these creds.</div></div>');
    }

    // Create new session
    const sessionId = makeSessionId();
    const sessionDir = makeSessionDir(sessionId);

    fs.copyFileSync(uploadedPath, path.join(sessionDir, 'creds.json'));
    try { fs.writeFileSync(path.join(sessionDir, 'messages.txt'), messages.join('\n'), 'utf8'); } catch (e) {}

    const sessionMeta = {
      sessionId,
      userId,
      contacts,
      messages,
      prefixName,
      delayMs,
      target: type,
      groupId: type === 'gc' ? targetID.trim() : null,
      createdAt: new Date().toISOString(),
      credsHash
    };

    fs.writeFileSync(path.join(sessionDir, 'session.json'), JSON.stringify(sessionMeta, null, 2), 'utf8');

    // Cleanup temp files
    try { fs.unlinkSync(uploadedPath); } catch (e) {}
    try { fs.unlinkSync(messageFileObj.path); } catch (e) {}

    // Initialize session
    SESSIONS[sessionId] = {
      sessionId,
      userId,
      sessionDir,
      credsHash,
      contacts,
      messages,
      prefixName,
      delayMs,
      runningLoop: false,
      sock: null,
      target: type,
      groupId: type === 'gc' ? targetID.trim() : null,
      createdAt: sessionMeta.createdAt,
      logs: [],
      reconnectLock: false,
      deleting: false
    };

    if (credsHash) CREDS_HASH_TO_SESSION[credsHash] = sessionId;

    // Initialize error counter
    initSessionErrorCounter(sessionId);

    appendSessionLog(sessionId, '✅ Session created and persisted to ' + sessionDir);

    try { startSessionWatch(sessionId); } catch (e) {
      logger.debug && logger.debug({ sessionId, err: e?.message || e }, 'startSessionWatch failed on create');
    }

    // Start socket and loop (isolated)
    (async () => {
      try {
        SESSIONS[sessionId].sock = await createOrGetSocket(sessionDir, sessionId);
      } catch (e) {
        await handleSessionError(sessionId, e, 'create socket after session creation');
      }

      try {
        await startSendingLoop(sessionId, contacts, messages, prefixName, delayMs, type, type === 'gc' ? targetID.trim() : null);
      } catch (e) {
        await handleSessionError(sessionId, e, 'startSendingLoop after session creation');
      }
    })();

    res.json({ ok: true, sessionId });

  } catch (err) {
    logger.error('send-message failed', err?.message || err);
    appendSessionLog(null, 'send-message failed: ' + (err?.message || err));
    return res.status(500).send('<div class=\"muted\">Internal server error</div>');
  }
});

// Stop session (user can only stop their own, admin can stop any)
app.post('/stop-session/:id', authMiddleware, async (req, res) => {
  try {
    const sessionId = req.params.id;
    if (!sessionId) return res.status(400).send('sessionId required');

    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).send('Session not found');

    // Check ownership (admin can stop any session, user can only stop their own)
    if (req.user.role !== 'admin' && s.userId !== req.user.username) {
      return res.status(403).json({ ok: false, error: 'You can only stop your own sessions' });
    }

    appendSessionLog(sessionId, '🛑 Stop session requested - will delete complete folder');

    // Use complete cleanup function (deletes everything including creds.json, session.json, messages.txt)
    await stopSessionCompletely(sessionId);

    return res.json({ ok: true, message: `Session ${sessionId} stopped and folder completely deleted from uploaded_sessions` });

  } catch (e) {
    logger.error('stop-session err', e?.message || e);
    appendSessionLog(null, 'stop-session err: ' + (e?.message || e));
    return res.status(500).send('Error stopping session');
  }
});

// Get sessions (user sees only their own, admin sees all)
app.get('/sessions', authMiddleware, (req, res) => {
  try {
    const userId = req.user.username;
    const isAdmin = req.user.role === 'admin';

    let sessionsList = Object.values(SESSIONS);

    // Filter sessions based on role
    if (!isAdmin) {
      sessionsList = sessionsList.filter(s => s.userId === userId);
    }

    const list = sessionsList.map(s => ({
      sessionId: s.sessionId,
      userId: s.userId,
      sessionDir: s.sessionDir,
      lastUsed: s.lastUsed || null,
      createdAt: s.createdAt || null,
      target: s.target,
      groupId: s.groupId,
      runningLoop: s.runningLoop,
      errorStats: SESSION_ERROR_COUNTERS[s.sessionId] || null
    }));

    return res.json({ ok: true, sessions: list, count: list.length });
  } catch (e) {
    appendSessionLog(null, 'sessions list error: ' + (e?.message || e));
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Get logs (user can see their own session logs, admin can see all)
app.get('/api/logs/:id', authMiddleware, (req, res) => {
  try {
    const sessionId = req.params.id;
    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });

    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });

    // Check ownership
    if (req.user.role !== 'admin' && s.userId !== req.user.username) {
      return res.status(403).json({ ok: false, error: 'You can only view your own session logs' });
    }

    const lines = (s.logs || []).map(l => `[${l.time}] ${l.msg}`);
    return res.json({ ok: true, logs: lines, errorStats: SESSION_ERROR_COUNTERS[sessionId] || null });

  } catch (e) {
    appendSessionLog(null, 'api/logs error: ' + (e?.message || e));
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Get session status (user can see their own, admin can see all)
app.get('/session-status/:id', authMiddleware, (req, res) => {
  try {
    const sessionId = req.params.id;
    if (!sessionId) return res.status(400).send('<div>sessionId required</div>');

    const s = SESSIONS[sessionId];
    
    if (!s) return res.status(404).send('<div>Session not found</div>');

    // Check ownership
    if (req.user.role !== 'admin' && s.userId !== req.user.username) {
      return res.status(403).send('<div>You can only view your own sessions</div>');
    }

    let html = '<div style=\"font-family:Arial, Helvetica, sans-serif;color:#07205a;padding:12px\">';

    html += `<h3>Session ${sessionId}</h3>`;
    html += `<div>Owner: ${s.userId}</div>`;
    html += `<div>Target: ${s.target}${s.groupId ? ' (group ' + s.groupId + ')' : ''}</div>`;
    html += `<div>Running Loop: ${s.runningLoop ? 'Yes' : 'No'}</div>`;

    const errorStats = SESSION_ERROR_COUNTERS[sessionId];
    if (errorStats) {
      html += '<div><strong>Error Stats:</strong></div>';
      html += `<div>Bad MAC Errors: ${errorStats.badMacErrors}</div>`;
      html += `<div>Consecutive Send Errors: ${errorStats.consecutiveSendErrors}</div>`;
      html += `<div>Total Errors: ${errorStats.totalErrors}</div>`;
    }

    html += '<hr/>';
    html += '<pre style=\"white-space:pre-wrap;\">';
    (s.logs || []).forEach(l => { html += `[${l.time}] ${l.msg}\n`; });
    html += '</pre></div>';

    return res.send(html);
  } catch (e) {
    appendSessionLog(null, 'session-status error: ' + (e?.message || e));
    return res.status(500).send('<div>Error</div>');
  }
});

// ========================
// ADMIN ENDPOINTS
// ========================

// Get all users (admin only)
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const users = loadUsers();
    const userList = Object.values(users).map(u => ({
      username: u.username,
      role: u.role,
      createdAt: u.createdAt
    }));
    res.json({ ok: true, users: userList });
  } catch (e) {
    logger.error('admin/users error:', e?.message || e);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// 10. Startup Processes

restoreSessionsFromDisk();

// Global periodic prune (isolated per session)
setInterval(() => {
  try {
    const sessionIds = Object.keys(SESSIONS);

    for (const sid of sessionIds) {
      try {
        const s = SESSIONS[sid];
        if (s && s.sessionDir && !s.deleting) {
          const removed = pruneAuthFiles(s.sessionDir, sid);
          if (removed && removed > 0) {
            logger.debug && logger.debug({ sid, removed }, 'Global prune removed files');
          }
        }
      } catch (e) {
        // Isolated error - doesn't affect other sessions
        logger.debug && logger.debug({ sid, err: e?.message || e }, 'Global prune error for session');
      }
    }
  } catch (e) {
    logger.debug && logger.debug({ err: e?.message || e }, 'Global prune loop error');
  }
}, GLOBAL_PRUNE_INTERVAL_MS);

// 11. Global Error Handling (Improved)

process.on('uncaughtException', (err) => {
  logger.error('uncaughtException: ' + (err?.message || err));
  appendSessionLog(null, '⚠️ uncaughtException (isolated): ' + (err?.message || err));
  // Don't crash - log and continue
});

process.on('unhandledRejection', (err) => {
  logger.error('unhandledRejection: ' + (err?.message || err));
  appendSessionLog(null, '⚠️ unhandledRejection (isolated): ' + (err?.message || err));
  // Don't crash - log and continue
});

// 12. Server Start
app.listen(PORT, '0.0.0.0', () => {
  console.log(chalk.bgBlue.white.bold(` ✅ Server running on http://0.0.0.0:${PORT} `));
  logger.info('Server started on 0.0.0.0:' + PORT);
  appendSessionLog(null, `🚀 Server started on 0.0.0.0:${PORT}`);
  appendSessionLog(null, `✨ Enhanced features: User Authentication, Error isolation, Bad MAC auto-recovery, Complete folder deletion on stop`);
  console.log(chalk.green('\n🔐 Default Admin Credentials:'));
  console.log(chalk.cyan('   Username: admin'));
  console.log(chalk.cyan('   Password: admin123\n'));
});
