'use strict';
/* ============================================================
   آزمون‌ساز کلاسی — Node.js + Express
   اجرا:  npm install  سپس  npm start
   همهٔ داده‌ها در پوشهٔ data/ ذخیره می‌شود.
============================================================ */
const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');
const os      = require('os');

const app  = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR    = path.join(__dirname, 'data');
const DB_FILE     = path.join(DATA_DIR, 'db.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');

app.disable('x-powered-by');
app.use(express.json({ limit: '12mb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));

/* ---------- ابزار ---------- */
const uid   = () => crypto.randomBytes(6).toString('hex');
const now   = () => Date.now();
const clone = o => JSON.parse(JSON.stringify(o));
const mean  = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0;
const median = a => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const shuffle = a => { const r = a.slice(); for (let i = r.length - 1; i > 0; i--) { const j = (Math.random() * (i + 1)) | 0; [r[i], r[j]] = [r[j], r[i]]; } return r; };
/* نرمال‌سازی متن فارسی برای تصحیح جای‌خالی */
const norm = s => String(s == null ? '' : s).trim().toLowerCase()
  .replace(/[۰-۹]/g, d => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)))
  .replace(/[٠-٩]/g, d => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
  .replace(/ي/g, 'ی').replace(/ك/g, 'ک')
  .replace(/[\u200c\u200e\u200f]/g, ' ').replace(/[\u064B-\u0652]/g, '')
  .replace(/\s+/g, ' ');
const UN_RE = /^[a-zA-Z0-9_.]{3,20}$/;
const JM = ['فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'];
function jdate(ts){
  const d = new Date(ts), gy = d.getFullYear(), gm = d.getMonth() + 1, gd = d.getDate();
  const gdm = [0,31,59,90,120,151,181,212,243,273,304,334];
  let jy = gy <= 1600 ? 0 : 979, gy2 = gy <= 1600 ? gy - 621 : gy - 1600, gy3 = gm > 2 ? gy2 + 1 : gy2;
  let days = 365*gy2 + Math.floor((gy3+3)/4) - Math.floor((gy3+99)/100) + Math.floor((gy3+399)/400) - 80 + gd + gdm[gm-1];
  jy += 33*Math.floor(days/12053); days %= 12053; jy += 4*Math.floor(days/1461); days %= 1461;
  if (days > 365) { jy += Math.floor((days-1)/365); days = (days-1)%365; }
  const jm = days < 186 ? 1 + Math.floor(days/31) : 7 + Math.floor((days-186)/30);
  const jd = 1 + (days < 186 ? days % 31 : (days-186) % 30);
  const p = n => String(n).padStart(2, '0');
  return jd + ' ' + JM[jm-1] + ' ' + jy + ' — ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

/* ---------- پایگاه‌دادهٔ فایلی (نوشتن اتمی) ---------- */
function loadSecret(){
  try { return fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch (e) {}
  const s = crypto.randomBytes(24).toString('hex');
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(SECRET_FILE, s);
  return s;
}
const SECRET = process.env.SECRET || loadSecret();

let db = null;
function saveDb(){
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
(function loadDb(){
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { db = null; }
  if (!db || !Array.isArray(db.users)) db = { users: [], classes: [], exams: [], attempts: [], bank: [] };
})();
function autoBackup(){
  try {
    if (!fs.existsSync(DB_FILE)) return;
    const stamp = new Date().toISOString().slice(0, 10);
    fs.copyFileSync(DB_FILE, path.join(DATA_DIR, 'backup-' + stamp + '.json'));
    const files = fs.readdirSync(DATA_DIR).filter(f => f.indexOf('backup-') === 0).sort();
    while (files.length > 7) fs.unlinkSync(path.join(DATA_DIR, files.shift()));
  } catch (e) { console.error('خطای پشتیبان‌گیری:', e.message); }
}
autoBackup();

/* ---------- کاربر، رمز، توکن ---------- */
const hash = (pw, salt) => crypto.scryptSync(String(pw), salt, 20).toString('hex');
function mkUser(role, name, username, password, extra){
  const salt = uid();
  return Object.assign({ id: uid(), role, name: String(name).trim(), username: String(username).trim().toLowerCase(), salt, passHash: hash(password, salt), active: true, createdAt: now() }, extra || {});
}
const pubUser = u => ({ id: u.id, role: u.role, name: u.name, username: u.username, createdAt: u.createdAt, classId: u.classId || null, className: (db.classes.find(c => c.id === u.classId) || {}).name || '' });

function sign(userId){
  const exp = now() + 30 * 864e5;
  const p = Buffer.from(userId + '|' + exp).toString('hex');
  return p + '.' + crypto.createHmac('sha256', SECRET).update(p).digest('hex');
}
function verify(t){
  try {
    const parts = String(t || '').split('.');
    if (parts.length !== 2) return null;
    const exp = crypto.createHmac('sha256', SECRET).update(parts[0]).digest('hex');
    if (exp.length !== parts[1].length || !crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(parts[1]))) return null;
    const dec = Buffer.from(parts[0], 'hex').toString().split('|');
    if (+dec[1] < now()) return null;
    return db.users.find(u => u.id === dec[0] && u.active !== false) || null;
  } catch (e) { return null; }
}
app.use('/api', (req, res, next) => {
  const h = req.headers.authorization || '';
  req.user = verify(h.indexOf('Bearer ') === 0 ? h.slice(7) : (req.query.t || null));
  next();
});
const need = roles => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'ابتدا وارد حساب خود شوید' });
  if (roles && roles.indexOf(req.user.role) < 0) return res.status(403).json({ error: 'برای این عملیات دسترسی ندارید' });
  next();
};
const wrap = fn => (req, res) => { try { fn(req, res); } catch (e) { console.error(e); res.status(500).json({ error: 'خطای داخلی سرور' }); } };

/* محدودسازی تلاش ناموفق ورود */
const fails = {};
function failTooMany(k){ const f = fails[k] = fails[k] || []; const t = now(); while (f.length && f[0] < t - 60000) f.shift(); return f.length >= 10; }

/* ---------- موتور تصحیح ---------- */
function recompute(at){
  let earned = 0, hasNull = false;
  for (const k in at.perQuestion) { const v = at.perQuestion[k]; if (v == null) hasNull = true; else earned += v; }
  at.earned = Math.round(earned * 100) / 100;
  at.score20 = at.totalPoints ? Math.round(Math.max(0, earned) / at.totalPoints * 2000) / 100 : 0;
  at.status = hasNull ? 'submitted' : 'graded';
}
function gradeAttempt(at, e){
  const pq = {}; let total = 0;
  at.order.forEach(qid => {
    const q = e.questions.find(x => x.id === qid); if (!q) return;
    total += +q.points || 0;
    const a = at.answers ? at.answers[qid] : undefined;
    let sc;
    if (q.type === 'essay') sc = (a == null || String(a).trim() === '') ? 0 : null;
    else if (q.type === 'mcq' || q.type === 'tf') sc = (a != null && String(q.correct[0]) === String(a)) ? +q.points : (a != null && e.negativeMark ? -(+q.points) * 0.25 : 0);
    else if (q.type === 'multi') {
      const sel = Array.isArray(a) ? a.map(String) : [];
      const corr = q.correct.map(String);
      if (!sel.length) sc = 0;
      else { const good = sel.filter(s => corr.indexOf(s) >= 0).length, bad = sel.length - good; sc = Math.max(0, (good - bad) / corr.length) * (+q.points); }
    } else if (q.type === 'blank') {
      const acc = String(q.accept || '').split('|').map(norm).filter(Boolean);
      sc = (a != null && acc.some(x => x === norm(a))) ? +q.points : (a != null && e.negativeMark ? -(+q.points) * 0.25 : 0);
    }
    pq[qid] = sc == null ? null : Math.round((sc + 1e-9) * 100) / 100;
  });
  at.perQuestion = pq; at.totalPoints = total; recompute(at);
}

/* ---------- آزمون: پاک‌سازی و اعتبارسنجی ---------- */
const findExam = id => db.exams.find(e => e.id === id);
const owns = (req, e) => req.user.role === 'teacher' && e.teacherId === req.user.id;
function prepQuestions(qs){
  return (qs || []).map(q => {
    q = clone(q);
    q.id = q.id || 'q' + uid();
    q.points = Math.abs(+q.points) || 1;
    q.type = ['mcq','multi','tf','blank','essay'].indexOf(q.type) >= 0 ? q.type : 'mcq';
    q.text = String(q.text || '').trim();
    q.explanation = String(q.explanation || '').trim();
    q.guideline = String(q.guideline || '').trim();
    q.accept = String(q.accept || '').trim();
    if (Array.isArray(q.options)) q.options = q.options.filter(o => String(o.text || '').trim()).map(o => ({ id: String(o.id || 'o' + uid()), text: String(o.text).trim() }));
    else q.options = [];
    if (q.type === 'mcq') q.correct = (q.correct || []).map(String).filter(c => q.options.some(o => o.id === c)).slice(0, 1);
    else if (q.type === 'multi') q.correct = (q.correct || []).map(String).filter(c => q.options.some(o => o.id === c));
    else if (q.type === 'tf') q.correct = ['t','f'].indexOf(String((q.correct || [])[0])) >= 0 ? [String(q.correct[0])] : [];
    else q.correct = [];
    return q;
  });
}
function validateExam(e){
  if (!String(e.title || '').trim()) return 'عنوان آزمون را وارد کنید';
  if (!(+e.duration > 0)) return 'مدت آزمون (دقیقه) را وارد کنید';
  if (!Array.isArray(e.questions) || !e.questions.length) return 'آزمون باید حداقل یک سؤال داشته باشد';
  for (const q of e.questions) {
    if (!q.text) return 'متن یکی از سؤال‌ها خالی است';
    if (!(+q.points > 0)) return 'بارم یکی از سؤال‌ها صفر است';
    if (q.type === 'mcq' && (q.options.length < 2 || !q.correct.length)) return 'سؤال چهارگزینه‌ای باید حداقل دو گزینه و یک پاسخ درست داشته باشد';
    if (q.type === 'multi' && !q.correct.length) return 'پاسخ درستِ سؤال چندگزینه‌ای را علامت بزنید';
    if (q.type === 'tf' && !q.correct.length) return 'پاسخِ سؤال صحیح/غلط را مشخص کنید';
    if (q.type === 'blank' && !q.accept) return 'پاسخ سؤال جای‌خالی را وارد کنید';
  }
  return null;
}

/* ---------- سازندهٔ پاسخ‌ها ---------- */
function orderedOpts(at, q){
  let opts = q.options || [];
  const oo = at.optionOrder && at.optionOrder[q.id];
  if (oo) { const m = {}; opts.forEach(o => { m[o.id] = o; }); opts = oo.map(id => m[id]).filter(Boolean); }
  return opts;
}
/* برای دانش‌آموز در حال آزمون — بدون هیچ پاسخ درستی */
function attemptPayload(at, e){
  const qs = [];
  at.order.forEach(qid => {
    const q = e.questions.find(x => x.id === qid); if (!q) return;
    const opts = orderedOpts(at, q);
    qs.push({ id: q.id, type: q.type, text: q.text, points: +q.points || 0, options: opts.map(o => ({ id: o.id, text: o.text })) });
  });
  return {
    attempt: { id: at.id, examId: e.id, remaining: Math.max(0, at.startedAt + at.duration * 60000 - now()), flags: at.flags || {}, answers: at.answers || {} },
    exam: { id: e.id, title: e.title, subject: e.subject, duration: e.duration, negativeMark: !!e.negativeMark, passMark: e.passMark },
    questions: qs
  };
}
/* پاسخ‌نامهٔ دانش‌آموز بعد از تحویل */
function reviewPayload(at, e){
  const allowed = !!e.showAnswers;
  const qs = at.order.map(qid => {
    const q = e.questions.find(x => x.id === qid); if (!q) return null;
    const opts = orderedOpts(at, q);
    return {
      id: q.id, type: q.type, text: q.text, points: +q.points || 0,
      options: opts.map(o => ({ id: o.id, text: o.text })),
      myAnswer: (at.answers && at.answers[qid] != null) ? at.answers[qid] : null,
      myScore: at.perQuestion ? (at.perQuestion[qid] == null ? null : at.perQuestion[qid]) : null,
      flagged: !!(at.flags && at.flags[qid]),
      correct: allowed ? q.correct : undefined,
      accept: allowed ? (q.accept || null) : undefined,
      explanation: allowed ? (q.explanation || null) : undefined
    };
  }).filter(Boolean);
  return {
    attempt: { id: at.id, examId: e.id, score20: at.score20, earned: at.earned, totalPoints: at.totalPoints, status: at.status, submittedAt: at.submittedAt, spentMin: Math.max(0, Math.round((at.submittedAt - at.startedAt) / 60000)), pass: at.score20 >= (e.passMark || 10) },
    exam: { id: e.id, title: e.title, subject: e.subject, passMark: e.passMark },
    questions: qs, showAnswers: allowed
  };
}
/* برگهٔ کامل برای معلم */
function paperPayload(at, e){
  const qs = at.order.map(qid => {
    const q = e.questions.find(x => x.id === qid); if (!q) return null;
    const opts = orderedOpts(at, q);
    return {
      id: q.id, type: q.type, text: q.text, points: +q.points || 0,
      options: opts.map(o => ({ id: o.id, text: o.text })),
      myAnswer: (at.answers && at.answers[qid] != null) ? at.answers[qid] : null,
      myScore: at.perQuestion ? (at.perQuestion[qid] == null ? null : at.perQuestion[qid]) : null,
      correct: q.correct, accept: q.accept || '', explanation: q.explanation || '', guideline: q.guideline || ''
    };
  }).filter(Boolean);
  const u = db.users.find(x => x.id === at.userId) || {};
  return {
    student: { name: u.name || '—', className: (db.classes.find(c => c.id === u.classId) || {}).name || '—' },
    attempt: { id: at.id, startedAt: at.startedAt, submittedAt: at.submittedAt, score20: at.score20, earned: at.earned, totalPoints: at.totalPoints, status: at.status, spentMin: Math.max(0, Math.round((at.submittedAt - at.startedAt) / 60000)) },
    exam: { id: e.id, title: e.title, passMark: e.passMark },
    questions: qs
  };
}

/* ---------- تحویل خودکار آزمون‌های سرِ موعد ---------- */
function finalizeExpired(filter){
  let changed = false;
  db.attempts.forEach(a => {
    if (!a.submittedAt && (!filter || filter(a))) {
      const e = findExam(a.examId);
      if (e && now() > a.startedAt + a.duration * 60000 + 3000) {
        a.submittedAt = a.startedAt + a.duration * 60000;
        gradeAttempt(a, e); changed = true;
      }
    }
  });
  if (changed) saveDb();
}
setInterval(() => finalizeExpired(), 30000).unref();

/* ============ راه‌اندازی اولیه و ثبت‌نام ============ */
app.get('/api/setup', (req, res) => res.json({ needsSetup: db.users.filter(u => u.role === 'teacher').length === 0 }));

app.post('/api/register/teacher', wrap((req, res) => {
  if (db.users.some(u => u.role === 'teacher')) return res.status(403).json({ error: 'حساب معلم از قبل وجود دارد؛ وارد شوید' });
  const b = req.body || {};
  if (!String(b.name || '').trim() || !String(b.username || '').trim() || String(b.password || '').length < 4)
    return res.status(400).json({ error: 'نام، نام کاربری و رمز (حداقل ۴ نویسه) الزامی است' });
  if (!UN_RE.test(String(b.username).trim())) return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۲۰ نویسهٔ لاتین یا عدد باشد' });
  if (db.users.some(u => u.username === String(b.username).trim().toLowerCase())) return res.status(409).json({ error: 'این نام کاربری قبلاً گرفته شده' });
  const u = mkUser('teacher', b.name, b.username, b.password);
  db.users.push(u); saveDb();
  res.json({ token: sign(u.id), user: pubUser(u) });
}));

app.post('/api/register/student', wrap((req, res) => {
  const b = req.body || {};
  const cls = db.classes.find(c => c.code === String(b.code || '').trim().toUpperCase());
  if (!cls) return res.status(404).json({ error: 'کد کلاس درست نیست — از معلم خود بپرسید' });
  if (!String(b.name || '').trim() || !String(b.username || '').trim() || String(b.password || '').length < 4)
    return res.status(400).json({ error: 'نام، نام کاربری و رمز (حداقل ۴ نویسه) الزامی است' });
  if (!UN_RE.test(String(b.username).trim())) return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۲۰ نویسهٔ لاتین یا عدد باشد (مثلاً sara12)' });
  const un = String(b.username).trim().toLowerCase();
  if (db.users.some(u => u.username === un)) return res.status(409).json({ error: 'این نام کاربری قبلاً گرفته شده — یکی دیگر انتخاب کنید' });
  const u = mkUser('student', b.name, un, b.password, { classId: cls.id });
  db.users.push(u); saveDb();
  res.json({ token: sign(u.id), user: pubUser(u) });
}));

app.post('/api/login', wrap((req, res) => {
  const b = req.body || {};
  const un = String(b.username || '').trim().toLowerCase();
  if (failTooMany(un)) return res.status(429).json({ error: 'تلاش‌های زیاد — یک دقیقه صبر کنید' });
  const u = db.users.find(x => x.username === un && x.active !== false);
  if (!u || hash(String(b.password || ''), u.salt) !== u.passHash) {
    (fails[un] = fails[un] || []).push(now());
    return res.status(401).json({ error: 'نام کاربری یا رمز عبور نادرست است' });
  }
  delete fails[un];
  res.json({ token: sign(u.id), user: pubUser(u) });
}));

app.get('/api/me', need(), wrap((req, res) => res.json({ user: pubUser(req.user) })));

app.post('/api/change-pass', need(), wrap((req, res) => {
  const b = req.body || {};
  if (hash(String(b.current || ''), req.user.salt) !== req.user.passHash) return res.status(400).json({ error: 'رمز فعلی نادرست است' });
  if (String(b.next || '').length < 4) return res.status(400).json({ error: 'رمز جدید باید حداقل ۴ نویسه باشد' });
  req.user.salt = uid(); req.user.passHash = hash(String(b.next), req.user.salt); saveDb();
  res.json({ ok: true });
}));

/* ============ کلاس‌ها ============ */
const clsFull = c => Object.assign({}, c, {
  teacher: (db.users.find(u => u.id === c.teacherId) || {}).name || '—',
  students: db.users.filter(u => u.role === 'student' && u.classId === c.id).map(u => ({ id: u.id, name: u.name, username: u.username }))
});
app.get('/api/classes', need(), wrap((req, res) => {
  let list = db.classes;
  if (req.user.role === 'teacher') list = list.filter(c => c.teacherId === req.user.id);
  else list = list.filter(c => c.id === req.user.classId);
  res.json({ classes: list.map(clsFull) });
}));
const randCode = () => { const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s = ''; for (let i = 0; i < 5; i++) s += A[(Math.random() * A.length) | 0]; return s; };
app.post('/api/classes', need('teacher'), wrap((req, res) => {
  const b = req.body || {};
  if (!String(b.name || '').trim()) return res.status(400).json({ error: 'نام کلاس الزامی است' });
  let code = String(b.code || '').trim().toUpperCase();
  if (code && db.classes.some(c => c.code === code)) return res.status(409).json({ error: 'این کد قبلاً استفاده شده — کد دیگری بگذارید' });
  if (!code) { do { code = randCode(); } while (db.classes.some(c => c.code === code)); }
  const c = { id: uid(), name: String(b.name).trim(), code, teacherId: req.user.id, createdAt: now() };
  db.classes.push(c); saveDb(); res.json({ class: clsFull(c) });
}));
app.patch('/api/classes/:id', need('teacher'), wrap((req, res) => {
  const c = db.classes.find(x => x.id === req.params.id);
  if (!c || c.teacherId !== req.user.id) return res.status(404).json({ error: 'کلاس یافت نشد' });
  const b = req.body || {};
  if (String(b.name || '').trim()) c.name = String(b.name).trim();
  if (b.code) {
    const code = String(b.code).trim().toUpperCase();
    if (db.classes.some(x => x.code === code && x.id !== c.id)) return res.status(409).json({ error: 'این کد تکراری است' });
    c.code = code;
  }
  saveDb(); res.json({ class: clsFull(c) });
}));
app.delete('/api/classes/:id', need('teacher'), wrap((req, res) => {
  const c = db.classes.find(x => x.id === req.params.id);
  if (!c || c.teacherId !== req.user.id) return res.status(404).json({ error: 'کلاس یافت نشد' });
  db.classes = db.classes.filter(x => x.id !== c.id);
  db.users.forEach(u => { if (u.classId === c.id) u.classId = null; });
  saveDb(); res.json({ ok: true });
}));
app.post('/api/classes/join', need('student'), wrap((req, res) => {
  const c = db.classes.find(x => x.code === String((req.body || {}).code || '').trim().toUpperCase());
  if (!c) return res.status(404).json({ error: 'کد کلاس درست نیست' });
  req.user.classId = c.id; saveDb();
  res.json({ class: clsFull(c) });
}));

/* مدیریت دانش‌آموز توسط معلمِ صاحب کلاس */
const ownsStudent = (t, u) => {
  if (t.role !== 'teacher' || !u || u.role !== 'student') return false;
  const c = db.classes.find(x => x.id === u.classId);
  return !!(c && c.teacherId === t.id);
};
app.patch('/api/students/:id', need('teacher'), wrap((req, res) => {
  const u = db.users.find(x => x.id === req.params.id);
  if (!ownsStudent(req.user, u)) return res.status(404).json({ error: 'دانش‌آموز یافت نشد' });
  const n = String((req.body || {}).name || '').trim();
  if (!n) return res.status(400).json({ error: 'نام جدید را وارد کنید' });
  u.name = n; saveDb(); res.json({ ok: true });
}));
app.post('/api/students/:id/reset-pass', need('teacher'), wrap((req, res) => {
  const u = db.users.find(x => x.id === req.params.id);
  if (!ownsStudent(req.user, u)) return res.status(404).json({ error: 'دانش‌آموز یافت نشد' });
  const pw = String((req.body || {}).password || '');
  if (pw.length < 4) return res.status(400).json({ error: 'رمز باید حداقل ۴ نویسه باشد' });
  u.salt = uid(); u.passHash = hash(pw, u.salt); saveDb();
  res.json({ ok: true });
}));
app.post('/api/classes/:id/remove-student', need('teacher'), wrap((req, res) => {
  const c = db.classes.find(x => x.id === req.params.id);
  if (!c || c.teacherId !== req.user.id) return res.status(404).json({ error: 'کلاس یافت نشد' });
  const u = db.users.find(x => x.id === (req.body || {}).userId);
  if (!u || u.classId !== c.id) return res.status(404).json({ error: 'این دانش‌آموز در کلاس شما نیست' });
  u.classId = null; saveDb(); res.json({ ok: true });
}));

/* ============ آزمون‌ها ============ */
app.get('/api/exams', need(), wrap((req, res) => {
  if (req.user.role === 'teacher') {
    const rows = db.exams.filter(e => e.teacherId === req.user.id).map(e => {
      const ats = db.attempts.filter(a => a.examId === e.id && a.submittedAt);
      const graded = ats.filter(a => a.status === 'graded');
      return {
        id: e.id, title: e.title, subject: e.subject, status: e.status, duration: e.duration,
        questionCount: e.questions.length, totalPoints: e.questions.reduce((s, q) => s + (+q.points || 0), 0),
        attemptLimit: e.attemptLimit, passMark: e.passMark,
        classes: e.classIds.map(id => (db.classes.find(c => c.id === id) || {}).name).filter(Boolean),
        attempts: ats.length, inProgress: db.attempts.filter(a => a.examId === e.id && !a.submittedAt).length,
        pendingEssays: ats.filter(a => a.status === 'submitted').length,
        avg: graded.length ? Math.round(mean(graded.map(a => a.score20)) * 100) / 100 : null,
        updatedAt: e.updatedAt
      };
    }).sort((a, b) => b.updatedAt - a.updatedAt);
    return res.json({ exams: rows });
  }
  /* دانش‌آموز */
  finalizeExpired(a => a.userId === req.user.id);
  const st = req.user;
  const rows = db.exams.filter(e => e.status === 'published' && e.classIds.indexOf(st.classId) >= 0).map(e => {
    const mine = db.attempts.filter(a => a.examId === e.id && a.userId === st.id);
    const open = mine.find(a => !a.submittedAt) || null;
    const done = mine.filter(a => a.submittedAt);
    return {
      id: e.id, title: e.title, subject: e.subject, duration: e.duration,
      questionCount: e.questions.length, totalPoints: e.questions.reduce((s, q) => s + (+q.points || 0), 0),
      attemptLimit: e.attemptLimit, passMark: e.passMark, negativeMark: !!e.negativeMark,
      teacher: (db.users.find(u => u.id === e.teacherId) || {}).name || '—',
      myAttempts: mine.length, myBest: done.length ? Math.max(...done.map(a => a.score20)) : null,
      openAttemptId: open ? open.id : null
    };
  });
  res.json({ exams: rows });
}));

app.post('/api/exams', need('teacher'), wrap((req, res) => {
  const b = req.body || {};
  const err = validateExam(b); if (err) return res.status(400).json({ error: err });
  const e = {
    id: uid(), title: String(b.title).trim(), subject: String(b.subject || 'عمومی').trim(),
    teacherId: req.user.id,
    classIds: (Array.isArray(b.classIds) ? b.classIds : []).filter(id => db.classes.some(c => c.id === id && c.teacherId === req.user.id)),
    status: 'draft', duration: +b.duration || 10,
    shuffleQ: !!b.shuffleQ, shuffleO: !!b.shuffleO, showAnswers: b.showAnswers !== false, negativeMark: !!b.negativeMark,
    attemptLimit: Math.max(0, +b.attemptLimit || 1), passMark: Math.min(20, Math.max(0, +b.passMark || 10)),
    randomCount: Math.max(0, +b.randomCount || 0),
    questions: prepQuestions(b.questions), createdAt: now(), updatedAt: now()
  };
  db.exams.push(e); saveDb(); res.json({ exam: e });
}));

app.get('/api/exams/:id', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  res.json({ exam: e });
}));

app.patch('/api/exams/:id', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  const b = req.body || {};
  const merged = Object.assign({}, e, b, {
    id: e.id, teacherId: e.teacherId, status: e.status, createdAt: e.createdAt,
    questions: b.questions !== undefined ? prepQuestions(b.questions) : e.questions,
    classIds: b.classIds !== undefined ? (Array.isArray(b.classIds) ? b.classIds : []).filter(id => db.classes.some(c => c.id === id && c.teacherId === req.user.id)) : e.classIds
  });
  const err = validateExam(merged); if (err) return res.status(400).json({ error: err });
  Object.assign(e, merged, { updatedAt: now() }); saveDb(); res.json({ exam: e });
}));

app.delete('/api/exams/:id', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  db.exams = db.exams.filter(x => x.id !== e.id);
  db.attempts = db.attempts.filter(a => a.examId !== e.id);
  saveDb(); res.json({ ok: true });
}));

app.post('/api/exams/:id/status', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  const st = (req.body || {}).status;
  if (['draft', 'published', 'closed'].indexOf(st) < 0) return res.status(400).json({ error: 'وضعیت نامعتبر است' });
  if (st === 'published' && !e.questions.length) return res.status(400).json({ error: 'آزمون بدون سؤال منتشر نمی‌شود' });
  if (st === 'closed') {
    /* بستن = تحویل و تصحیحِ همهٔ آزمون‌های در جریان، همان لحظه */
    db.attempts.forEach(a => {
      if (a.examId === e.id && !a.submittedAt) { a.submittedAt = now(); gradeAttempt(a, e); }
    });
  }
  e.status = st; e.updatedAt = now(); saveDb();
  res.json({ ok: true, status: st });
}));

app.post('/api/exams/:id/duplicate', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  const c = clone(e);
  c.id = uid(); c.title = e.title + ' (کپی)'; c.status = 'draft';
  c.createdAt = c.updatedAt = now();
  db.exams.push(c); saveDb(); res.json({ ok: true });
}));

/* ============ شرکت در آزمون (دانش‌آموز) ============ */
app.post('/api/exams/:id/start', need('student'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || e.status !== 'published' || e.classIds.indexOf(req.user.classId) < 0)
    return res.status(404).json({ error: 'آزمون فعالی برای کلاس شما یافت نشد' });
  finalizeExpired(a => a.userId === req.user.id && a.examId === e.id);
  const mine = db.attempts.filter(a => a.examId === e.id && a.userId === req.user.id);
  const open = mine.find(a => !a.submittedAt);
  if (open) return res.json(attemptPayload(open, e));
  if (e.attemptLimit > 0 && mine.length >= e.attemptLimit)
    return res.status(403).json({ error: 'به سقف شرکت در این آزمون رسیده‌اید' });
  let qs = e.questions;
  if (e.randomCount > 0 && e.randomCount < qs.length) qs = shuffle(qs).slice(0, e.randomCount);
  const order = (e.shuffleQ ? shuffle(qs) : qs).map(q => q.id);
  const optionOrder = {};
  e.questions.forEach(q => {
    if ((q.type === 'mcq' || q.type === 'multi') && e.shuffleO && (q.options || []).length > 1)
      optionOrder[q.id] = shuffle(q.options.map(o => o.id));
  });
  const at = { id: uid(), examId: e.id, userId: req.user.id, startedAt: now(), duration: e.duration, order, optionOrder, answers: {}, flags: {}, perQuestion: null, submittedAt: null, status: 'in-progress', lastSeen: now() };
  db.attempts.push(at); saveDb();
  res.json(attemptPayload(at, e));
}));

app.post('/api/attempts/:id/answer', need('student'), wrap((req, res) => {
  const at = db.attempts.find(a => a.id === req.params.id && a.userId === req.user.id);
  const e = at && findExam(at.examId);
  if (!at || !e) return res.status(404).json({ error: 'آزمون یافت نشد' });
  if (at.submittedAt) return res.status(400).json({ error: 'این آزمون قبلاً تحویل شده است' });
  if (now() > at.startedAt + at.duration * 60000 + 3000) {
    at.submittedAt = at.startedAt + at.duration * 60000; gradeAttempt(at, e); saveDb();
    return res.json({ expired: true });
  }
  const b = req.body || {};
  if (at.order.indexOf(b.qid) < 0) return res.status(400).json({ error: 'سؤال نامعتبر است' });
  if (b.value === null || b.value === undefined) delete at.answers[b.qid];
  else at.answers[b.qid] = b.value;
  at.lastSeen = now(); saveDb();
  res.json({ ok: true });
}));

app.post('/api/attempts/:id/flag', need('student'), wrap((req, res) => {
  const at = db.attempts.find(a => a.id === req.params.id && a.userId === req.user.id);
  if (!at || at.submittedAt) return res.status(400).json({ error: 'امکان تغییر نیست' });
  const b = req.body || {};
  at.flags = at.flags || {}; at.flags[b.qid] = !!b.on; at.lastSeen = now(); saveDb();
  res.json({ ok: true });
}));

app.post('/api/attempts/:id/finish', need('student'), wrap((req, res) => {
  const at = db.attempts.find(a => a.id === req.params.id && a.userId === req.user.id);
  const e = at && findExam(at.examId);
  if (!at || !e) return res.status(404).json({ error: 'آزمون یافت نشد' });
  if (!at.submittedAt) {
    /* پاسخ‌های لحظهٔ آخر (متنِ تازه‌تایپ‌شده) هم همراه تحویل می‌آید */
    const body = req.body || {};
    const dl = at.startedAt + at.duration * 60000;
    if (body.answers && now() <= dl + 10000) {
      Object.keys(body.answers).forEach(qid => {
        if (at.order.indexOf(qid) >= 0) {
          const v = body.answers[qid];
          if (v === null || v === undefined) delete at.answers[qid]; else at.answers[qid] = v;
        }
      });
    }
    at.submittedAt = Math.min(now(), dl);
    gradeAttempt(at, e); at.lastSeen = now(); saveDb();
  }
  res.json(reviewPayload(at, e));
}));

app.get('/api/attempts/:id', need('student'), wrap((req, res) => {
  const at = db.attempts.find(a => a.id === req.params.id && a.userId === req.user.id);
  const e = at && findExam(at.examId);
  if (!at || !e) return res.status(404).json({ error: 'یافت نشد' });
  if (!at.submittedAt) return res.status(400).json({ error: 'این آزمون هنوز تحویل نشده است' });
  res.json(reviewPayload(at, e));
}));

app.get('/api/me/attempts', need(), wrap((req, res) => {
  res.json({ attempts: db.attempts.filter(a => a.userId === req.user.id && a.submittedAt)
    .map(a => { const e = findExam(a.examId) || {}; return { id: a.id, examTitle: e.title || '—', subject: e.subject || '', score20: a.score20, status: a.status, submittedAt: a.submittedAt, pass: a.score20 >= (e.passMark || 10) }; })
    .sort((a, b) => b.submittedAt - a.submittedAt) });
}));

/* ============ داده‌های معلم ============ */
app.get('/api/exams/:id/attempts', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  finalizeExpired(a => a.examId === e.id);
  res.json({ attempts: db.attempts.filter(a => a.examId === e.id && a.submittedAt)
    .map(a => { const u = db.users.find(x => x.id === a.userId) || {}; return { id: a.id, name: u.name || '—', className: (db.classes.find(c => c.id === u.classId) || {}).name || '—', score20: a.score20, status: a.status, submittedAt: a.submittedAt, spentMin: Math.max(0, Math.round((a.submittedAt - a.startedAt) / 60000)), pass: a.score20 >= (e.passMark || 10) }; })
    .sort((a, b) => b.score20 - a.score20) });
}));

app.get('/api/exams/:id/attempts/:aid', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  const at = db.attempts.find(a => a.id === req.params.aid && a.examId === e.id);
  if (!at || !at.submittedAt) return res.status(404).json({ error: 'پاسخ‌برگ یافت نشد' });
  res.json(paperPayload(at, e));
}));

app.get('/api/exams/:id/live', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  finalizeExpired(a => a.examId === e.id);
  res.json({ duration: e.duration, rows: db.attempts.filter(a => a.examId === e.id)
    .map(a => {
      const u = db.users.find(x => x.id === a.userId) || {}; const done = !!a.submittedAt;
      return { id: a.id, name: u.name || '—', className: (db.classes.find(c => c.id === u.classId) || {}).name || '—', done,
        answered: a.order.filter(qid => a.answers && a.answers[qid] != null).length, total: a.order.length,
        remaining: done ? 0 : Math.max(0, a.startedAt + a.duration * 60000 - now()),
        lastSeen: a.lastSeen || a.startedAt, score20: done ? a.score20 : null, status: a.status };
    })
    .sort((a, b) => (a.done - b.done) || (b.lastSeen - a.lastSeen)) });
}));

app.get('/api/exams/:id/analytics', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  const ats = db.attempts.filter(a => a.examId === e.id && a.submittedAt);
  const scores = ats.map(a => a.score20);
  const B = [0, 0, 0, 0, 0];
  scores.forEach(s => { if (s < 5) B[0]++; else if (s < 10) B[1]++; else if (s < 15) B[2]++; else if (s < 18) B[3]++; else B[4]++; });
  res.json({
    count: ats.length,
    mean: scores.length ? Math.round(mean(scores) * 100) / 100 : null,
    median: scores.length ? Math.round(median(scores) * 100) / 100 : null,
    max: scores.length ? Math.max(...scores) : null, min: scores.length ? Math.min(...scores) : null,
    passRate: scores.length ? Math.round(scores.filter(s => s >= (e.passMark || 10)).length / scores.length * 100) : null,
    buckets: B,
    qstats: e.questions.map((q, i) => {
      const vals = ats.map(a => a.perQuestion ? a.perQuestion[q.id] : null).filter(v => v != null);
      return { id: q.id, no: i + 1, text: q.text, type: q.type, points: +q.points,
        avg: vals.length ? Math.round(mean(vals) / q.points * 1000) / 10 : null,
        full: vals.filter(v => v >= q.points).length, zero: vals.filter(v => v <= 0).length, n: vals.length };
    })
  });
}));

app.get('/api/exams/:id/export', need('teacher'), wrap((req, res) => {
  const e = findExam(req.params.id);
  if (!e || !owns(req, e)) return res.status(404).json({ error: 'آزمون یافت نشد' });
  finalizeExpired(a => a.examId === e.id);
  const rows = db.attempts.filter(a => a.examId === e.id && a.submittedAt)
    .map(a => {
      const u = db.users.find(x => x.id === a.userId) || {};
      return [u.name || '—', (db.classes.find(c => c.id === u.classId) || {}).name || '—',
        a.status === 'graded' ? 'نهایی' : 'در انتظار تشریحی', a.score20,
        Math.round(a.score20 / 20 * 100), jdate(a.submittedAt),
        Math.max(0, Math.round((a.submittedAt - a.startedAt) / 60000))];
    })
    .sort((a, b) => b[3] - a[3]);
  const head = ['نام و نام خانوادگی', 'کلاس', 'وضعیت', 'نمره از ۲۰', 'درصد', 'تاریخ تحویل', 'مدت (دقیقه)'];
  const csv = '\uFEFF' + head.join(',') + '\n' + rows.map(r => r.map(c => '"' + String(c).replace(/"/g, '""') + '"').join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="results.csv"');
  res.send(csv);
}));

app.get('/api/grading', need('teacher'), wrap((req, res) => {
  const mine = {}; db.exams.forEach(e => { if (e.teacherId === req.user.id) mine[e.id] = 1; });
  res.json({ items: db.attempts.filter(a => a.submittedAt && a.status === 'submitted' && mine[a.examId])
    .map(a => {
      const u = db.users.find(x => x.id === a.userId) || {}; const e = findExam(a.examId) || {};
      return { attemptId: a.id, examId: a.examId, student: u.name || '—', examTitle: e.title || '—', submittedAt: a.submittedAt, pending: Object.values(a.perQuestion || {}).filter(v => v == null).length };
    })
    .sort((a, b) => b.submittedAt - a.submittedAt) });
}));

app.post('/api/attempts/:id/grade', need('teacher'), wrap((req, res) => {
  const at = db.attempts.find(a => a.id === req.params.id);
  if (!at || !at.submittedAt) return res.status(404).json({ error: 'پاسخ‌برگ یافت نشد' });
  const e = findExam(at.examId);
  if (!e || !owns(req, e)) return res.status(403).json({ error: 'دسترسی ندارید' });
  if (!at.perQuestion) return res.status(400).json({ error: 'این پاسخ‌برگ آمادهٔ تصحیح نیست' });
  const b = req.body || {};
  const q = e.questions.find(x => x.id === b.qid);
  if (!q) return res.status(400).json({ error: 'سؤال نامعتبر است' });
  at.perQuestion[b.qid] = Math.round(Math.max(0, Math.min(+q.points, +b.score || 0)) * 100) / 100;
  recompute(at); saveDb();
  res.json({ qid: b.qid, score: at.perQuestion[b.qid], status: at.status, score20: at.score20 });
}));

/* ============ بانک سؤال ============ */
app.get('/api/bank', need('teacher'), wrap((req, res) => {
  let list = db.bank.filter(q => q.teacherId === req.user.id);
  if (req.query.subject) list = list.filter(q => q.subject === req.query.subject);
  res.json({ questions: list });
}));
app.post('/api/bank', need('teacher'), wrap((req, res) => {
  const b = req.body || {};
  if (!String(b.text || '').trim()) return res.status(400).json({ error: 'متن سؤال الزامی است' });
  const q = prepQuestions([b])[0];
  q.teacherId = req.user.id; q.subject = String(b.subject || 'عمومی').trim();
  db.bank.push(q); saveDb(); res.json({ question: q });
}));
app.delete('/api/bank/:id', need('teacher'), wrap((req, res) => {
  db.bank = db.bank.filter(x => !(x.id === req.params.id && x.teacherId === req.user.id));
  saveDb(); res.json({ ok: true });
}));

/* ============ آمار، رتبه‌بندی، تنظیمات ============ */
app.get('/api/stats', need(), wrap((req, res) => {
  const atts = db.attempts.filter(a => a.submittedAt);
  const recent = list => list.slice(-8).reverse().map(a => {
    const u = db.users.find(x => x.id === a.userId) || {}; const e = findExam(a.examId) || {};
    return { name: u.name || '—', exam: e.title || '—', score: a.score20, at: a.submittedAt };
  });
  if (req.user.role === 'teacher') {
    const myExams = db.exams.filter(e => e.teacherId === req.user.id);
    const ids = {}; myExams.forEach(e => { ids[e.id] = 1; });
    const mine = atts.filter(a => ids[a.examId]);
    const myClassIds = db.classes.filter(c => c.teacherId === req.user.id).map(c => c.id);
    res.json({ role: 'teacher',
      classes: myClassIds.length,
      students: db.users.filter(u => u.role === 'student' && myClassIds.indexOf(u.classId) >= 0).length,
      exams: { total: myExams.length, published: myExams.filter(e => e.status === 'published').length },
      attempts: mine.length,
      avg: mine.length ? Math.round(mean(mine.map(a => a.score20)) * 100) / 100 : null,
      pending: mine.filter(a => a.status === 'submitted').length,
      myExams: myExams.map(e => { const g = atts.filter(a => a.examId === e.id && a.status === 'graded'); return { id: e.id, title: e.title, attempts: atts.filter(a => a.examId === e.id).length, avg: g.length ? Math.round(mean(g.map(x => x.score20)) * 100) / 100 : null }; }),
      recent: recent(mine) });
  } else {
    const mine = atts.filter(a => a.userId === req.user.id);
    const avail = db.exams.filter(e => e.status === 'published' && e.classIds.indexOf(req.user.classId) >= 0).length;
    res.json({ role: 'student',
      attempts: mine.length,
      avg: mine.length ? Math.round(mean(mine.map(a => a.score20)) * 100) / 100 : null,
      best: mine.length ? Math.max(...mine.map(a => a.score20)) : null,
      passed: mine.filter(a => { const e = findExam(a.examId); return e && a.score20 >= (e.passMark || 10); }).length,
      available: avail, recent: recent(mine) });
  }
}));

app.get('/api/leaderboard', need(), wrap((req, res) => {
  let atts = db.attempts.filter(a => a.submittedAt && a.status === 'graded');
  if (req.user.role === 'teacher') {
    const mine = {}; db.exams.forEach(e => { if (e.teacherId === req.user.id) mine[e.id] = 1; });
    atts = atts.filter(a => mine[a.examId]);
  } else {
    const ids = {}; db.users.forEach(u => { if (u.role === 'student' && u.classId === req.user.classId) ids[u.id] = 1; });
    atts = atts.filter(a => ids[a.userId]);
  }
  const by = {};
  atts.forEach(a => { (by[a.userId] = by[a.userId] || []).push(a.score20); });
  const rows = Object.keys(by).map(id => {
    const u = db.users.find(x => x.id === id) || {}; const arr = by[id];
    return { userId: id, name: u.name || '—', className: (db.classes.find(c => c.id === u.classId) || {}).name || '—', avg: Math.round(mean(arr) * 100) / 100, count: arr.length, best: Math.max(...arr) };
  }).sort((a, b) => b.avg - a.avg).slice(0, 20);
  let myRank = null;
  if (req.user.role === 'student') rows.forEach((r, i) => { if (r.userId === req.user.id) myRank = i + 1; });
  res.json({ rows, myRank });
}));

app.get('/api/backup', need('teacher'), wrap((req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="azmoonsaz-backup.json"');
  res.send(JSON.stringify(db));
}));
app.post('/api/restore', need('teacher'), wrap((req, res) => {
  const b = req.body;
  if (!b || !Array.isArray(b.users) || !Array.isArray(b.exams) || !Array.isArray(b.classes))
    return res.status(400).json({ error: 'فایل پشتیبان معتبر نیست' });
  db = { users: b.users || [], classes: b.classes || [], exams: b.exams || [], attempts: b.attempts || [], bank: b.bank || [] };
  saveDb(); res.json({ ok: true });
}));
app.post('/api/teachers', need('teacher'), wrap((req, res) => {
  const b = req.body || {};
  if (!String(b.name || '').trim() || !String(b.username || '').trim() || String(b.password || '').length < 4)
    return res.status(400).json({ error: 'نام، نام کاربری و رمز (حداقل ۴ نویسه) الزامی است' });
  if (!UN_RE.test(String(b.username).trim())) return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۲۰ نویسهٔ لاتین باشد' });
  const un = String(b.username).trim().toLowerCase();
  if (db.users.some(u => u.username === un)) return res.status(409).json({ error: 'این نام کاربری گرفته شده' });
  const u = mkUser('teacher', b.name, un, b.password);
  db.users.push(u); saveDb(); res.json({ ok: true });
}));

/* ---------- ۴۰۴ و خطا ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'مسیر یافت نشد' }));
app.use((err, req, res, next) => { if (err) return res.status(400).json({ error: 'درخواست نامعتبر است' }); next(); });
process.on('SIGINT', () => { try { saveDb(); } catch (e) {} process.exit(0); });

/* ---------- شروع ---------- */
app.listen(PORT, '0.0.0.0', () => {
  const ips = [];
  const nets = os.networkInterfaces();
  Object.keys(nets).forEach(k => nets[k].forEach(n => { if (n.family === 'IPv4' && !n.internal) ips.push(n.address); }));
  console.log('\n  ------------------------------------------');
  console.log('   آزمون‌ساز آماده است');
  console.log('   روی این رایانه:    http://localhost:' + PORT);
  ips.forEach(ip => console.log('   برای دانش‌آموزان:  http://' + ip + ':' + PORT));
  if (!ips.length) console.log('   (آدرسی برای اتصال دانش‌آموزان پیدا نشد — به Wi-Fi وصل شوید)');
  console.log('   داده‌ها در پوشهٔ data/ ذخیره می‌شوند');
  console.log('  ------------------------------------------\n');
});