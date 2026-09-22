require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const OTP_MINUTES = Number(process.env.OTP_EXPIRES_MINUTES || 10);

if (!JWT_SECRET) console.warn('WARNING: JWT_SECRET is not set. Set it in Render Environment Variables.');
if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) console.warn('WARNING: Gmail SMTP credentials are not set. OTP email cannot be sent until configured.');

const dataDir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'ludobest2.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  mobile TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_otp_email_purpose ON otp_codes(email, purpose);
`);

const transporter = (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD)
  ? nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD } })
  : null;

const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false, message: { ok:false, message:'অনেকবার চেষ্টা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));

function normalizeEmail(v){ return String(v || '').trim().toLowerCase(); }
function normalizeMobile(v){ return String(v || '').replace(/[\s-]/g,'').trim(); }
function validName(v){ return /^[\p{L} .'-]{2,60}$/u.test(String(v || '').trim()); }
function validMobile(v){ return /^(?:\+?8801|01)[3-9]\d{8}$/.test(normalizeMobile(v)); }
function validEmail(v){ return /^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(normalizeEmail(v)); }
function generateOtp(){ return String(Math.floor(100000 + Math.random()*900000)); }
function signToken(user){
  if (!JWT_SECRET) throw new Error('JWT_SECRET is not configured');
  return jwt.sign({ sub:user.id, email:user.email }, JWT_SECRET, { expiresIn:'7d' });
}
function auth(req,res,next){
  try {
    const h=req.headers.authorization||'';
    if(!h.startsWith('Bearer ')) return res.status(401).json({ok:false,message:'লগইন প্রয়োজন।'});
    const p=jwt.verify(h.slice(7),JWT_SECRET);
    const user=db.prepare('SELECT id,name,mobile,email,email_verified,created_at FROM users WHERE id=?').get(p.sub);
    if(!user || !user.email_verified) return res.status(401).json({ok:false,message:'অ্যাকাউন্ট যাচাই করা হয়নি।'});
    req.user=user; next();
  } catch(e){ return res.status(401).json({ok:false,message:'সেশন শেষ হয়েছে। আবার লগইন করুন।'}); }
}

async function sendOtp(email, purpose){
  if(!transporter) throw new Error('Gmail OTP is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD.');
  const code=generateOtp();
  const hash=await bcrypt.hash(code, 10);
  const expires=Date.now()+OTP_MINUTES*60*1000;
  db.prepare('UPDATE otp_codes SET used=1 WHERE email=? AND purpose=? AND used=0').run(email,purpose);
  db.prepare('INSERT INTO otp_codes(email,purpose,code_hash,expires_at) VALUES(?,?,?,?,?)'.replace('VALUES(?,?,?,?,?)','VALUES(?,?,?,?)')).run(email,purpose,hash,expires);
  await transporter.sendMail({
    from:`Ludo Best 2 <${process.env.GMAIL_USER}>`, to:email,
    subject:`Ludo Best 2 - Your ${purpose === 'signup' ? 'Sign Up' : 'Login'} OTP`,
    text:`Your Ludo Best 2 OTP is ${code}. It expires in ${OTP_MINUTES} minutes. Do not share this code with anyone.`,
    html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0f172a;color:#fff;border-radius:16px"><h2>Ludo Best 2</h2><p>Your verification code is:</p><div style="font-size:32px;letter-spacing:8px;font-weight:700;background:#1e293b;padding:18px;text-align:center;border-radius:12px">${code}</div><p>This code expires in ${OTP_MINUTES} minutes. Never share your OTP.</p></div>`
  });
}

app.post('/api/auth/signup/send-otp', otpLimiter, async (req,res)=>{
  try{
    const name=String(req.body.name||'').trim(), mobile=normalizeMobile(req.body.mobile), email=normalizeEmail(req.body.email);
    if(!validName(name)) return res.status(400).json({ok:false,message:'সঠিক নাম দিন।'});
    if(!validMobile(mobile)) return res.status(400).json({ok:false,message:'সঠিক বাংলাদেশি মোবাইল নম্বর দিন।'});
    if(!validEmail(email)) return res.status(400).json({ok:false,message:'সঠিক Gmail/Email দিন।'});
    const exists=db.prepare('SELECT id,email_verified FROM users WHERE email=? OR mobile=?').get(email,mobile);
    if(exists && exists.email_verified) return res.status(409).json({ok:false,message:'এই Gmail বা মোবাইল আগে থেকেই রেজিস্টার করা আছে।'});
    if(exists && !exists.email_verified) db.prepare('DELETE FROM users WHERE id=?').run(exists.id);
    db.prepare('INSERT INTO users(name,mobile,email,email_verified) VALUES(?,?,?,0)').run(name,mobile,email);
    await sendOtp(email,'signup');
    res.json({ok:true,message:'Gmail-এ OTP পাঠানো হয়েছে।'});
  }catch(e){ console.error(e); res.status(500).json({ok:false,message:e.message.includes('Gmail OTP')?e.message:'OTP পাঠানো যায়নি। Gmail configuration যাচাই করুন।'}); }
});

app.post('/api/auth/signup/verify-otp', authLimiter, async (req,res)=>{
  try{
    const email=normalizeEmail(req.body.email), code=String(req.body.otp||'').trim();
    const row=db.prepare('SELECT * FROM otp_codes WHERE email=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1').get(email,'signup');
    if(!row) return res.status(400).json({ok:false,message:'OTP পাওয়া যায়নি। আবার OTP নিন।'});
    if(Date.now()>row.expires_at) return res.status(400).json({ok:false,message:'OTP-এর মেয়াদ শেষ।'});
    if(row.attempts>=5) return res.status(429).json({ok:false,message:'অনেকবার ভুল OTP দেওয়া হয়েছে। আবার OTP নিন।'});
    const match=await bcrypt.compare(code,row.code_hash);
    if(!match){ db.prepare('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?').run(row.id); return res.status(400).json({ok:false,message:'ভুল OTP।'}); }
    db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);
    const user=db.prepare('UPDATE users SET email_verified=1 WHERE email=? RETURNING id,name,mobile,email,email_verified,created_at').get(email);
    const token=signToken(user);
    res.json({ok:true,message:'Sign up সফল হয়েছে।',token,user});
  }catch(e){console.error(e);res.status(500).json({ok:false,message:'Verification failed।'});}
});

app.post('/api/auth/login/send-otp', otpLimiter, async (req,res)=>{
  try{
    const email=normalizeEmail(req.body.email);
    if(!validEmail(email)) return res.status(400).json({ok:false,message:'সঠিক Gmail দিন।'});
    const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if(!user || !user.email_verified) return res.status(401).json({ok:false,message:'অ্যাকাউন্ট পাওয়া যায়নি বা verify করা হয়নি।'});
    await sendOtp(email,'login');
    res.json({ok:true,message:'Login OTP Gmail-এ পাঠানো হয়েছে।'});
  }catch(e){console.error(e);res.status(500).json({ok:false,message:e.message.includes('Gmail OTP')?e.message:'OTP পাঠানো যায়নি।'});}
});

app.post('/api/auth/login/verify-otp', authLimiter, async (req,res)=>{
  try{
    const email=normalizeEmail(req.body.email), code=String(req.body.otp||'').trim();
    const row=db.prepare('SELECT * FROM otp_codes WHERE email=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1').get(email,'login');
    if(!row) return res.status(400).json({ok:false,message:'OTP পাওয়া যায়নি।'});
    if(Date.now()>row.expires_at) return res.status(400).json({ok:false,message:'OTP-এর মেয়াদ শেষ।'});
    if(row.attempts>=5) return res.status(429).json({ok:false,message:'অনেকবার ভুল OTP দেওয়া হয়েছে। আবার OTP নিন।'});
    const match=await bcrypt.compare(code,row.code_hash);
    if(!match){db.prepare('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?').run(row.id);return res.status(400).json({ok:false,message:'ভুল OTP।'});}
    db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);
    const user=db.prepare('SELECT id,name,mobile,email,email_verified,created_at FROM users WHERE email=?').get(email);
    const token=signToken(user);
    res.json({ok:true,message:'Login সফল হয়েছে।',token,user});
  }catch(e){console.error(e);res.status(500).json({ok:false,message:'Login verification failed।'});}
});

app.post('/api/auth/resend', otpLimiter, async (req,res)=>{
  try{
    const email=normalizeEmail(req.body.email), purpose=req.body.purpose==='login'?'login':'signup';
    if(!validEmail(email)) return res.status(400).json({ok:false,message:'সঠিক Gmail দিন।'});
    if(purpose==='signup' && !db.prepare('SELECT id FROM users WHERE email=? AND email_verified=0').get(email)) return res.status(400).json({ok:false,message:'Sign up তথ্য আবার দিন।'});
    if(purpose==='login' && !db.prepare('SELECT id FROM users WHERE email=? AND email_verified=1').get(email)) return res.status(400).json({ok:false,message:'অ্যাকাউন্ট পাওয়া যায়নি।'});
    await sendOtp(email,purpose); res.json({ok:true,message:'নতুন OTP পাঠানো হয়েছে।'});
  }catch(e){res.status(500).json({ok:false,message:'OTP পাঠানো যায়নি।'});}
});

app.get('/api/me', auth, (req,res)=>res.json({ok:true,user:req.user}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.listen(PORT,()=>console.log(`Ludo Best 2 running on port ${PORT}`));
