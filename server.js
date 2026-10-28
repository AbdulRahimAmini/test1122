require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const crypto     = require('crypto');

const app = express();

// ─── 1. Helmet (Security Headers) ────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrcAttr: ["'unsafe-inline'"],           // inline event handlers
      styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      styleSrcElem:  ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:       ["'self'", "https://fonts.gstatic.com"],
      imgSrc:        ["'self'", "data:", "blob:"],
      connectSrc:    ["'self'"],
    }
  }
}));

app.use(express.json({ limit: '10mb' }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.static(path.join(__dirname, 'public')));

// ─── 2. Rate Limiting ─────────────────────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 دقیقه
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'تعداد درخواست‌ها بیش از حد مجاز است. لطفاً ۱۵ دقیقه صبر کنید.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,                     // حداکثر ۱۰ تلاش ورود در ۱۵ دقیقه
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'تعداد تلاش‌های ورود بیش از حد است. لطفاً ۱۵ دقیقه صبر کنید.' }
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);   // سخت‌تر برای login

// ─── 3. Encryption (AES-256-GCM) ─────────────────────────────────────────────
// برای تولید کلید: openssl rand -hex 32
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;  // 64-char hex
const ENC_PREFIX = 'enc:v1:';

function encryptData(obj) {
  if (!ENCRYPTION_KEY) return obj;   // اگر کلید نباشد، بدون رمز ذخیره شود
  try {
    const iv  = crypto.randomBytes(12);
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ENC_PREFIX + [iv.toString('hex'), tag.toString('hex'), enc.toString('hex')].join(':');
  } catch (e) {
    console.error('Encryption error:', e.message);
    return obj;
  }
}

function decryptData(val) {
  // اگر plain object باشد (داده‌های قدیمی)، همان را برگردان
  if (!val || typeof val !== 'string' || !val.startsWith(ENC_PREFIX)) return val;
  try {
    const [ivHex, tagHex, dataHex] = val.slice(ENC_PREFIX.length).split(':');
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    const dec = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
    return JSON.parse(dec.toString('utf8'));
  } catch (e) {
    console.error('Decryption error:', e.message);
    return null;
  }
}

// ─── 4. Redis Cache ───────────────────────────────────────────────────────────
// اگر REDIS_URL نباشد، از in-memory Map به عنوان fallback استفاده می‌شود
let redisClient = null;
const memCache  = new Map();
const CACHE_TTL = 60;  // seconds

if (process.env.REDIS_URL) {
  try {
    const Redis = require('ioredis');
    redisClient = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy: (t) => Math.min(t * 100, 3000)
    });
    redisClient.on('connect', () => console.log('✓ Redis connected'));
    redisClient.on('error', (e) => {
      console.warn('⚠ Redis error (fallback to memory):', e.message);
      redisClient = null;
    });
  } catch (e) {
    console.warn('⚠ ioredis not installed — skipping Redis');
  }
}

async function cacheGet(key) {
  try {
    if (redisClient) {
      const v = await redisClient.get(key);
      return v ? JSON.parse(v) : null;
    }
    const e = memCache.get(key);
    if (!e) return null;
    if (Date.now() > e.exp) { memCache.delete(key); return null; }
    return e.val;
  } catch { return null; }
}

async function cacheSet(key, value, ttl = CACHE_TTL) {
  try {
    if (redisClient) await redisClient.setex(key, ttl, JSON.stringify(value));
    else memCache.set(key, { val: value, exp: Date.now() + ttl * 1000 });
  } catch (e) { console.warn('Cache set failed:', e.message); }
}

async function cacheDel(...keys) {
  for (const key of keys) {
    try {
      if (redisClient) await redisClient.del(key);
      else memCache.delete(key);
    } catch {}
  }
}

const ck = (username, type) => `finance:${username}:${type}`;

// ─── MongoDB Schema ───────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username:     { type: String, required: true, unique: true, trim: true },
  passwordHash: { type: String, required: true },
  data: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      income: [],
      expenses: [],
      goals: [],
      debts: [],
      openingBalance: { afn: 0, title: 'موجودی اولیه', cur: 'AFN', raw: 0 }
    }
  },
  config: {
    type: mongoose.Schema.Types.Mixed,
    default: { primaryCurrency: 'USD', rate: 88, rateLabel: 'بازار' }
  }
}, { timestamps: true });

// ─── Index روی createdAt ──────────────────────────────────────────────────────
// username ایندکس دارد چون unique: true است — دوباره تعریف نمی‌کنیم
userSchema.index({ createdAt: -1 });

const User = mongoose.model('User', userSchema);

// ─── JWT ──────────────────────────────────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET || 'change-me-in-production';
const JWT_EXPIRES = '30d';

function signToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'توکن معتبر نیست' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'توکن منقضی یا نامعتبر است' });
  }
}

// ─── Seed ─────────────────────────────────────────────────────────────────────
async function seedUsers() {
  if ((await User.countDocuments()) === 0) {
    const hash = await bcrypt.hash('1234', 10);
    await User.insertMany([
      { username: 'admin', passwordHash: hash },
      { username: 'کاربر', passwordHash: hash }
    ]);
    console.log('✓ Default users created: admin/1234 and کاربر/1234');
  }
}

// ─── DB Readiness ─────────────────────────────────────────────────────────────
app.use('/api', (req, res, next) => {
  if (mongoose.connection.readyState !== 1)
    return res.status(503).json({ error: 'در حال اتصال به پایگاه داده...' });
  next();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Auth Routes
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });

    const user = await User.findOne({ username: username.trim() });
    if (!user) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

    res.json({ token: signToken(user.username), username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.post('/api/auth/change', requireAuth, async (req, res) => {
  try {
    const { newUsername, newPassword } = req.body;
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

    if (newUsername && newUsername.trim() !== user.username) {
      if (await User.findOne({ username: newUsername.trim() }))
        return res.status(409).json({ error: 'این نام کاربری قبلاً وجود دارد' });
      await cacheDel(ck(user.username, 'data'), ck(user.username, 'stats'));
      user.username = newUsername.trim();
    }
    if (newPassword) user.passwordHash = await bcrypt.hash(newPassword, 10);
    if (!newUsername && !newPassword)
      return res.status(400).json({ error: 'هیچ تغییری ارسال نشده' });

    await user.save();
    res.json({ token: signToken(user.username), username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Data Routes
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/data — با کش
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const cached = await cacheGet(ck(req.user.username, 'data'));
    if (cached) return res.json(cached);

    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

    const data = decryptData(user.data) || {};
    await cacheSet(ck(req.user.username, 'data'), data);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// ─── 5. Pagination + Filter ──────────────────────────────────────────────────
// GET /api/report?from=YYYY-MM&to=YYYY-MM&page=1&limit=50
app.get('/api/report', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

    const rawData = decryptData(user.data) || {};
    const { from, to } = req.query;
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 50));

    const filterByMonth = (arr) => (arr || []).filter(x => {
      const m = (x.date || '').slice(0, 7);
      if (from && m < from) return false;
      if (to   && m > to)   return false;
      return true;
    });

    // Pagination wrapper
    const paginate = (arr) => {
      const total = arr.length;
      const start = (page - 1) * limit;
      return {
        items: arr.slice(start, start + limit),
        pagination: { total, page, limit, pages: Math.ceil(total / limit) }
      };
    };

    res.json({
      ...rawData,
      income:    paginate(filterByMonth(rawData.income)),
      expenses:  paginate(filterByMonth(rawData.expenses)),
      _filtered: !!(from || to),
      _from: from || null,
      _to:   to   || null
    });
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// ─── Aggregation: GET /api/stats ─────────────────────────────────────────────
// جمع درآمد و هزینه به تفکیک ماه — با MongoDB aggregation pipeline
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const cached = await cacheGet(ck(req.user.username, 'stats'));
    if (cached) return res.json(cached);

    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

    const isEncrypted = typeof user.data === 'string' && user.data.startsWith(ENC_PREFIX);
    let stats;

    if (!isEncrypted) {
      // ── MongoDB Aggregation Pipeline ──────────────────────────────────────
      const [result] = await User.aggregate([
        { $match: { username: req.user.username } },
        {
          $facet: {
            incomeByMonth: [
              { $unwind: { path: '$data.income', preserveNullAndEmpty: true } },
              { $match: { 'data.income': { $ne: null } } },
              {
                $group: {
                  _id:   { $substr: ['$data.income.date', 0, 7] },
                  total: { $sum: '$data.income.raw' },
                  count: { $sum: 1 }
                }
              },
              { $sort: { _id: 1 } }
            ],
            expensesByMonth: [
              { $unwind: { path: '$data.expenses', preserveNullAndEmpty: true } },
              { $match: { 'data.expenses': { $ne: null } } },
              {
                $group: {
                  _id:   { $substr: ['$data.expenses.date', 0, 7] },
                  total: { $sum: '$data.expenses.raw' },
                  count: { $sum: 1 }
                }
              },
              { $sort: { _id: 1 } }
            ]
          }
        }
      ]);
      stats = result || { incomeByMonth: [], expensesByMonth: [] };
    } else {
      // ── Application-level aggregation (وقتی data رمزنگاری شده) ──────────
      const rawData = decryptData(user.data) || {};
      const groupByMonth = (arr) => {
        const map = {};
        (arr || []).forEach(x => {
          const k = (x.date || '').slice(0, 7);
          if (!k) return;
          if (!map[k]) map[k] = { _id: k, total: 0, count: 0 };
          map[k].total += x.raw || 0;
          map[k].count += 1;
        });
        return Object.values(map).sort((a, b) => a._id.localeCompare(b._id));
      };
      stats = {
        incomeByMonth:   groupByMonth(rawData.income),
        expensesByMonth: groupByMonth(rawData.expenses)
      };
    }

    await cacheSet(ck(req.user.username, 'stats'), stats, 120);
    res.json(stats);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// PUT /api/data — رمزنگاری و invalidate cache
app.put('/api/data', requireAuth, async (req, res) => {
  try {
    const encrypted = encryptData(req.body);
    await User.updateOne(
      { username: req.user.username },
      { $set: { data: encrypted } }
    );
    await cacheDel(ck(req.user.username, 'data'), ck(req.user.username, 'stats'));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.get('/api/config', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
    res.json(user.config || { primaryCurrency: 'USD', rate: 88, rateLabel: 'بازار' });
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.put('/api/config', requireAuth, async (req, res) => {
  try {
    await User.updateOne(
      { username: req.user.username },
      { $set: { config: req.body } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// ─── SPA Fallback ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT      = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error('✗ MONGO_URI is not set');
  process.exit(1);
}

app.listen(PORT, () => console.log(`✓ Server running on port ${PORT}`));

mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✓ MongoDB connected');
    await seedUsers();
  })
  .catch(err => {
    console.error('✗ MongoDB connection failed:', err.message);
  });

mongoose.connection.on('disconnected', () => console.warn('⚠ MongoDB disconnected'));
mongoose.connection.on('reconnected',  () => console.log('✓ MongoDB reconnected'));
