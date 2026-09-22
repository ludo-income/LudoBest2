require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || '';
const OTP_MINUTES = Math.max(2, Number(process.env.OTP_EXPIRES_MINUTES || 10));
const OTP_MAX_ATTEMPTS = 5;

if (!JWT_SECRET) console.warn('WARNING: JWT_SECRET is not set.');
if (!process.env.BREVO_API_KEY || !process.env.BREVO_SENDER_EMAIL) console.warn('WARNING: Brevo email variables are not set.');
if (!process.env.DATABASE_URL) console.warn('WARNING: DATABASE_URL is not set. Add a Render PostgreSQL database for persistent users/admin data.');

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false } })
  : null;

const memory = { users: [], otps: [], paymentMethods: [], settings: {} };
let memoryId = 1;

async function q(text, params = []) {
  if (pool) return pool.query(text, params);
  // Minimal fallback for local UI testing when DATABASE_URL is absent.
  const t = text.replace(/\s+/g, ' ').trim().toLowerCase();
  if (t.startsWith('select count(*) from users')) return { rows: [{ count: String(memory.users.length) }] };
  if (t.includes('select id,name,mobile,email,email_verified,status,created_at from users where email=')) {
    const email = params[0]; const u = memory.users.find(x => x.email === email); return { rows: u ? [u] : [] };
  }
  if (t.includes('select * from users where email=')) { const u = memory.users.find(x => x.email === params[0]); return { rows: u ? [u] : [] }; }
  if (t.includes('select id from users where email=')) { const u = memory.users.find(x => x.email === params[0]); return { rows: u ? [{id:u.id}] : [] }; }
  if (t.includes('select id from users where mobile=')) { const u = memory.users.find(x => x.mobile === params[0]); return { rows: u ? [{id:u.id}] : [] }; }
  if (t.includes('select id,email_verified from users where email=')) { const u = memory.users.find(x => x.email === params[0]); return { rows: u ? [{id:u.id,email_verified:u.email_verified}] : [] }; }
  if (t.includes('select id,name,mobile,email,email_verified,created_at from users where id=')) { const u = memory.users.find(x => x.id === Number(params[0])); return { rows: u ? [u] : [] }; }
  if (t.includes('select id,name,mobile,email,email_verified,created_at from users where email=')) { const u = memory.users.find(x => x.email === params[0]); return { rows: u ? [u] : [] }; }
  if (t.startsWith('delete from users where id=')) { const id=Number(params[0]); memory.users=memory.users.filter(x=>x.id!==id); return {rows:[]}; }
  if (t.startsWith('update users set email_verified=1 where email=')) { const u=memory.users.find(x=>x.email===params[0]); if(u)u.email_verified=true; return {rows:u?[u]:[]}; }
  if (t.startsWith('update users set status=')) { const u=memory.users.find(x=>x.id===Number(params[2]||params[1])); if(u)u.status=params[0]; return {rows:u?[u]:[]}; }
  if (t.startsWith('insert into users')) { const [name,mobile,email]=params; const u={id:memoryId++,name,mobile,email,email_verified:false,status:'active',created_at:new Date().toISOString()}; memory.users.push(u); return {rows:[u]}; }
  if (t.includes('select * from otp_codes')) { const email=params[0],purpose=params[1]; const rows=memory.otps.filter(x=>x.email===email&&x.purpose===purpose&&!x.used).sort((a,b)=>b.id-a.id); return {rows:rows.slice(0,1)}; }
  if (t.startsWith('update otp_codes set used=1 where email=')) { memory.otps.filter(x=>x.email===params[0]&&x.purpose===params[1]&&!x.used).forEach(x=>x.used=true); return {rows:[]}; }
  if (t.startsWith('update otp_codes set used=1 where id=')) { const o=memory.otps.find(x=>x.id===Number(params[0])); if(o)o.used=true; return {rows:[]}; }
  if (t.startsWith('update otp_codes set attempts=attempts+1 where id=')) { const o=memory.otps.find(x=>x.id===Number(params[0])); if(o)o.attempts++; return {rows:[]}; }
  if (t.startsWith('insert into otp_codes')) { const [email,purpose,code_hash,expires_at]=params; memory.otps.push({id:memoryId++,email,purpose,code_hash,expires_at,attempts:0,used:false}); return {rows:[]}; }
  if (t.startsWith('select id,name,mobile,email,email_verified,status,created_at from users order by')) { return {rows:[...memory.users].sort((a,b)=>b.id-a.id)}; }
  if (t.startsWith('select id,name,mobile,email,email_verified,status,created_at from users where id=')) { const u=memory.users.find(x=>x.id===Number(params[0])); return {rows:u?[u]:[]}; }
  if (t.startsWith('select id,name,mobile,email,email_verified,status,created_at from users')) return {rows:memory.users};
  if (t.startsWith('select id,name,account_number,image_url,instructions,enabled,created_at from payment_methods')) return {rows:memory.paymentMethods};
  if (t.startsWith('select id,name,account_number,image_url,instructions,enabled,created_at from payment_methods where id=')) { const p=memory.paymentMethods.find(x=>x.id===Number(params[0])); return {rows:p?[p]:[]}; }
  if (t.startsWith('insert into payment_methods')) { const [name,account_number,image_url,instructions,enabled]=params; const p={id:memoryId++,name,account_number,image_url,instructions,enabled:enabled!==false,created_at:new Date().toISOString()}; memory.paymentMethods.push(p); return {rows:[p]}; }
  if (t.startsWith('update payment_methods')) { const id=Number(params[params.length-1]); const p=memory.paymentMethods.find(x=>x.id===id); if(p){p.name=params[0]??p.name;p.account_number=params[1]??p.account_number;p.image_url=params[2]??p.image_url;p.instructions=params[3]??p.instructions;p.enabled=params[4]??p.enabled;} return {rows:p?[p]:[]}; }
  if (t.startsWith('delete from payment_methods')) { const id=Number(params[0]); memory.paymentMethods=memory.paymentMethods.filter(x=>x.id!==id); return {rows:[]}; }
  return {rows:[]};
}

async function initDb(){
  if(!pool) return;
  await q(`CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    mobile TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS otp_codes (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE INDEX IF NOT EXISTS idx_otp_email_purpose ON otp_codes(email,purpose)`);
  await q(`CREATE TABLE IF NOT EXISTS payment_methods (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    account_number TEXT NOT NULL DEFAULT '',
    image_url TEXT NOT NULL DEFAULT '',
    instructions TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}

function normalizeEmail(v){ return String(v || '').trim().toLowerCase(); }
function normalizeMobile(v){ return String(v || '').replace(/[\s-]/g,'').trim(); }
function validName(v){ return /^[\p{L} .'-]{2,60}$/u.test(String(v || '').trim()); }
function validMobile(v){ return /^(?:\+?8801|01)[3-9]\d{8}$/.test(normalizeMobile(v)); }
function validEmail(v){ return /^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(normalizeEmail(v)); }
function generateOtp(){ return String(Math.floor(100000 + Math.random()*900000)); }
function signToken(payload){ if(!JWT_SECRET) throw new Error('JWT_SECRET is not configured'); return jwt.sign(payload,JWT_SECRET,{expiresIn:'7d'}); }
function auth(req,res,next){ try { const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return res.status(401).json({ok:false,message:'লগইন প্রয়োজন।'}); const p=jwt.verify(h.slice(7),JWT_SECRET); req.auth=p; next(); } catch(e){ return res.status(401).json({ok:false,message:'সেশন শেষ হয়েছে। আবার লগইন করুন।'}); } }
function adminAuth(req,res,next){ try { const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return res.status(401).json({ok:false,message:'Admin login প্রয়োজন।'}); const p=jwt.verify(h.slice(7),JWT_SECRET); if(p.role!=='admin') throw new Error('not admin'); req.admin=p; next(); } catch(e){ return res.status(401).json({ok:false,message:'Admin authorization failed।'}); } }

async function sendBrevoOtp(email,purpose){
  if(!process.env.BREVO_API_KEY || !process.env.BREVO_SENDER_EMAIL) throw new Error('Brevo OTP is not configured. Set BREVO_API_KEY and BREVO_SENDER_EMAIL.');
  const code=generateOtp();
  const hash=await bcrypt.hash(code,10);
  const expires=Date.now()+OTP_MINUTES*60*1000;
  await q('UPDATE otp_codes SET used=TRUE WHERE email=$1 AND purpose=$2 AND used=FALSE',[email,purpose]);
  await q('INSERT INTO otp_codes(email,purpose,code_hash,expires_at) VALUES($1,$2,$3,$4)',[email,purpose,hash,expires]);
  const kind=purpose==='signup'?'Sign Up':'Login';
  const resp=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'accept':'application/json','api-key':process.env.BREVO_API_KEY,'content-type':'application/json'},body:JSON.stringify({sender:{email:process.env.BREVO_SENDER_EMAIL,name:process.env.BREVO_SENDER_NAME||'Ludo Best 2'},to:[{email}],subject:`Ludo Best 2 - ${kind} OTP`,htmlContent:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0f172a;color:#fff;border-radius:16px"><h2>Ludo Best 2</h2><p>Your ${kind} verification code is:</p><div style="font-size:32px;letter-spacing:8px;font-weight:700;background:#1e293b;padding:18px;text-align:center;border-radius:12px">${code}</div><p>This code expires in ${OTP_MINUTES} minutes. Never share your OTP.</p></div>`})});
  if(!resp.ok){ const body=await resp.text(); console.error('Brevo error:',body); throw new Error('Brevo could not send the OTP email.'); }
}

const otpLimiter=rateLimit({windowMs:15*60*1000,max:5,standardHeaders:true,legacyHeaders:false,message:{ok:false,message:'অনেকবার OTP request হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।'}});
const authLimiter=rateLimit({windowMs:15*60*1000,max:30,standardHeaders:true,legacyHeaders:false});
app.use(express.json({limit:'100kb'}));
app.use(express.urlencoded({extended:false}));
app.use(express.static(path.join(__dirname,'..','public')));

app.get('/health',(req,res)=>res.json({ok:true,service:'Ludo Best 2'}));

app.post('/api/auth/signup/send-otp',otpLimiter,async(req,res)=>{try{
  const name=String(req.body.name||'').trim(),mobile=normalizeMobile(req.body.mobile),email=normalizeEmail(req.body.email);
  if(!validName(name)) return res.status(400).json({ok:false,message:'সঠিক নাম দিন।'});
  if(!validMobile(mobile)) return res.status(400).json({ok:false,message:'সঠিক বাংলাদেশি মোবাইল নম্বর দিন।'});
  if(!validEmail(email)) return res.status(400).json({ok:false,message:'শুধু Gmail address ব্যবহার করুন।'});
  const existingEmail=(await q('SELECT id,email_verified FROM users WHERE email=$1',[email])).rows[0];
  const existingMobile=(await q('SELECT id FROM users WHERE mobile=$1',[mobile])).rows[0];
  if(existingEmail?.email_verified) return res.status(409).json({ok:false,message:'এই Gmail আগে থেকেই registered।'});
  if(existingMobile && (!existingEmail || existingMobile.id!==existingEmail.id)) return res.status(409).json({ok:false,message:'এই মোবাইল নম্বর আগে থেকেই registered।'});
  if(existingEmail && !existingEmail.email_verified) await q('DELETE FROM users WHERE id=$1',[existingEmail.id]);
  await q('INSERT INTO users(name,mobile,email,email_verified,status) VALUES($1,$2,$3,FALSE,$4)',[name,mobile,email,'active']);
  await sendBrevoOtp(email,'signup');
  res.json({ok:true,message:'Gmail-এ OTP পাঠানো হয়েছে।'});
}catch(e){console.error(e);res.status(500).json({ok:false,message:e.message.includes('Brevo')?e.message:'OTP পাঠানো যায়নি।'});}});

async function verifyOtp(email,code,purpose){
  const row=(await q('SELECT * FROM otp_codes WHERE email=$1 AND purpose=$2 AND used=FALSE ORDER BY id DESC LIMIT 1',[email,purpose])).rows[0];
  if(!row) throw Object.assign(new Error('OTP পাওয়া যায়নি। আবার OTP নিন।'),{status:400});
  if(Date.now()>Number(row.expires_at)) throw Object.assign(new Error('OTP-এর মেয়াদ শেষ।'),{status:400});
  if(Number(row.attempts)>=OTP_MAX_ATTEMPTS) throw Object.assign(new Error('অনেকবার ভুল OTP দেওয়া হয়েছে। আবার OTP নিন।'),{status:429});
  const match=await bcrypt.compare(code,row.code_hash);
  if(!match){await q('UPDATE otp_codes SET attempts=attempts+1 WHERE id=$1',[row.id]);throw Object.assign(new Error('ভুল OTP।'),{status:400});}
  await q('UPDATE otp_codes SET used=TRUE WHERE id=$1',[row.id]);
}

app.post('/api/auth/signup/verify-otp',authLimiter,async(req,res)=>{try{
  const email=normalizeEmail(req.body.email),code=String(req.body.otp||'').trim(); if(!validEmail(email)||!/^[0-9]{6}$/.test(code)) return res.status(400).json({ok:false,message:'সঠিক Gmail ও ৬ সংখ্যার OTP দিন।'});
  await verifyOtp(email,code,'signup');
  const user=(await q('UPDATE users SET email_verified=TRUE WHERE email=$1 RETURNING id,name,mobile,email,email_verified,status,created_at',[email])).rows[0];
  if(!user) return res.status(404).json({ok:false,message:'Sign Up তথ্য পাওয়া যায়নি।'});
  const token=signToken({sub:String(user.id),email:user.email,role:'user'}); res.json({ok:true,message:'Sign Up সফল হয়েছে।',token,user});
}catch(e){res.status(e.status||500).json({ok:false,message:e.message||'Verification failed।'});}});

app.post('/api/auth/login/send-otp',otpLimiter,async(req,res)=>{try{
  const email=normalizeEmail(req.body.email); if(!validEmail(email)) return res.status(400).json({ok:false,message:'সঠিক Gmail দিন।'});
  const user=(await q('SELECT * FROM users WHERE email=$1',[email])).rows[0];
  if(!user||!user.email_verified) return res.status(401).json({ok:false,message:'অ্যাকাউন্ট পাওয়া যায়নি বা verify করা হয়নি।'});
  if(user.status!=='active') return res.status(403).json({ok:false,message:'এই account বর্তমানে blocked।'});
  await sendBrevoOtp(email,'login'); res.json({ok:true,message:'Login OTP Gmail-এ পাঠানো হয়েছে।'});
}catch(e){console.error(e);res.status(500).json({ok:false,message:e.message.includes('Brevo')?e.message:'OTP পাঠানো যায়নি।'});}});

app.post('/api/auth/login/verify-otp',authLimiter,async(req,res)=>{try{
  const email=normalizeEmail(req.body.email),code=String(req.body.otp||'').trim(); if(!validEmail(email)||!/^[0-9]{6}$/.test(code)) return res.status(400).json({ok:false,message:'সঠিক Gmail ও ৬ সংখ্যার OTP দিন।'});
  await verifyOtp(email,code,'login'); const user=(await q('SELECT id,name,mobile,email,email_verified,status,created_at FROM users WHERE email=$1',[email])).rows[0];
  if(!user||!user.email_verified) return res.status(401).json({ok:false,message:'Account verify করা হয়নি।'}); if(user.status!=='active') return res.status(403).json({ok:false,message:'এই account blocked।'});
  const token=signToken({sub:String(user.id),email:user.email,role:'user'}); res.json({ok:true,message:'Login সফল হয়েছে।',token,user});
}catch(e){res.status(e.status||500).json({ok:false,message:e.message||'Login verification failed।'});}});

app.post('/api/auth/resend',otpLimiter,async(req,res)=>{try{const email=normalizeEmail(req.body.email),purpose=req.body.purpose==='login'?'login':'signup';if(!validEmail(email))return res.status(400).json({ok:false,message:'সঠিক Gmail দিন।'});const user=(await q('SELECT * FROM users WHERE email=$1',[email])).rows[0];if(purpose==='signup'&&(!user||user.email_verified))return res.status(400).json({ok:false,message:'Sign Up তথ্য আবার দিন।'});if(purpose==='login'&&(!user||!user.email_verified))return res.status(400).json({ok:false,message:'অ্যাকাউন্ট পাওয়া যায়নি।'});await sendBrevoOtp(email,purpose);res.json({ok:true,message:'নতুন OTP পাঠানো হয়েছে।'});}catch(e){res.status(500).json({ok:false,message:'OTP পাঠানো যায়নি।'});}});
app.get('/api/me',auth,async(req,res)=>{const user=(await q('SELECT id,name,mobile,email,email_verified,status,created_at FROM users WHERE id=$1',[req.auth.sub])).rows[0];if(!user||user.status!=='active')return res.status(401).json({ok:false});res.json({ok:true,user});});

// Admin authentication and dashboard foundation.
app.post('/api/admin/login',authLimiter,async(req,res)=>{try{const email=normalizeEmail(req.body.email),password=String(req.body.password||'');if(!process.env.ADMIN_EMAIL||!process.env.ADMIN_PASSWORD_HASH)return res.status(503).json({ok:false,message:'Admin credentials Render Environment Variables-এ সেট করা হয়নি।'});if(email!==normalizeEmail(process.env.ADMIN_EMAIL))return res.status(401).json({ok:false,message:'Invalid admin credentials।'});const ok=await bcrypt.compare(password,process.env.ADMIN_PASSWORD_HASH);if(!ok)return res.status(401).json({ok:false,message:'Invalid admin credentials।'});const token=signToken({email,role:'admin'});res.json({ok:true,token,admin:{email}});}catch(e){res.status(500).json({ok:false,message:'Admin login failed।'});}});
app.get('/api/admin/me',adminAuth,(req,res)=>res.json({ok:true,admin:{email:req.admin.email}}));
app.get('/api/admin/stats',adminAuth,async(req,res)=>{const users=await q('SELECT COUNT(*)::int AS count FROM users');const verified=pool?await q('SELECT COUNT(*)::int AS count FROM users WHERE email_verified=TRUE'): {rows:[{count:memory.users.filter(u=>u.email_verified).length}]};const active=pool?await q("SELECT COUNT(*)::int AS count FROM users WHERE status='active'"):{rows:[{count:memory.users.filter(u=>u.status==='active').length}]};const pm=await q('SELECT COUNT(*)::int AS count FROM payment_methods');res.json({ok:true,stats:{users:Number(users.rows[0].count),verified:Number(verified.rows[0].count),active:Number(active.rows[0].count),paymentMethods:Number(pm.rows[0].count)}});});
app.get('/api/admin/users',adminAuth,async(req,res)=>{const r=await q('SELECT id,name,mobile,email,email_verified,status,created_at FROM users ORDER BY id DESC');res.json({ok:true,users:r.rows});});
app.patch('/api/admin/users/:id/status',adminAuth,async(req,res)=>{const status=req.body.status==='blocked'?'blocked':'active';const r=await q('UPDATE users SET status=$1 WHERE id=$2 RETURNING id,name,mobile,email,email_verified,status,created_at',[status,req.params.id]);if(!r.rows[0])return res.status(404).json({ok:false,message:'User পাওয়া যায়নি।'});res.json({ok:true,user:r.rows[0]});});
app.get('/api/admin/payment-methods',adminAuth,async(req,res)=>{const r=await q('SELECT id,name,account_number,image_url,instructions,enabled,created_at FROM payment_methods ORDER BY id DESC');res.json({ok:true,paymentMethods:r.rows});});
app.post('/api/admin/payment-methods',adminAuth,async(req,res)=>{const {name='',account_number='',image_url='',instructions='',enabled=true}=req.body;if(!String(name).trim())return res.status(400).json({ok:false,message:'Payment method name দিন।'});const r=await q('INSERT INTO payment_methods(name,account_number,image_url,instructions,enabled) VALUES($1,$2,$3,$4,$5) RETURNING id,name,account_number,image_url,instructions,enabled,created_at',[name,account_number,image_url,instructions,!!enabled]);res.json({ok:true,paymentMethod:r.rows[0]});});
app.patch('/api/admin/payment-methods/:id',adminAuth,async(req,res)=>{const {name='',account_number='',image_url='',instructions='',enabled=true}=req.body;const r=await q('UPDATE payment_methods SET name=$1,account_number=$2,image_url=$3,instructions=$4,enabled=$5 WHERE id=$6 RETURNING id,name,account_number,image_url,instructions,enabled,created_at',[name,account_number,image_url,instructions,!!enabled,req.params.id]);if(!r.rows[0])return res.status(404).json({ok:false,message:'Payment method পাওয়া যায়নি।'});res.json({ok:true,paymentMethod:r.rows[0]});});
app.delete('/api/admin/payment-methods/:id',adminAuth,async(req,res)=>{await q('DELETE FROM payment_methods WHERE id=$1',[req.params.id]);res.json({ok:true,message:'Deleted'});});

app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'..','public','admin.html')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));

initDb().then(()=>app.listen(PORT,()=>console.log(`Ludo Best 2 running on port ${PORT}`))).catch(err=>{console.error('Database init failed:',err);process.exit(1);});
