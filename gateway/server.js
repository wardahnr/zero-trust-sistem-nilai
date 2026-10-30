require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../src/db');
const { signAccessToken, signServiceToken, verifyToken, hashToken, GATEWAY_SECRET } = require('../src/security');
const { decide, deviceRegistered } = require('../src/policy');
const { audit } = require('../src/audit');

const app = express();
app.use(express.json());
const PORT = Number(process.env.PORT_GATEWAY || 3000);
const NILAI = `http://localhost:${process.env.PORT_NILAI || 3001}`;
const TRANSKRIP = `http://localhost:${process.env.PORT_TRANSKRIP || 3002}`;

function bearer(req) {
  const value = req.headers.authorization || '';
  return value.startsWith('Bearer ') ? value.slice(7) : null;
}
function fail(res, status, message) { return res.status(status).json({ error: message }); }

app.get('/health', (req,res) => res.json({ service:'gateway', status:'ok' }));

app.post('/auth/login', (req,res) => {
  const { username, password } = req.body || {};
  const deviceId = req.header('X-Device-ID');
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username || '');
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    audit({subject: username || 'unknown', endpoint:req.path, deviceId, decision:'deny', reason:'Kredensial salah'});
    return fail(res, 401, 'Username atau password salah');
  }
  if (!deviceRegistered(user.id, deviceId)) {
    audit({subject:user.username, endpoint:req.path, deviceId, decision:'deny', reason:'Device tidak terdaftar'});
    return fail(res, 403, 'Device tidak terdaftar untuk user ini');
  }
  const accessToken = signAccessToken(user);
  const refreshToken = crypto.randomBytes(48).toString('hex');
  const days = Number(process.env.REFRESH_TOKEN_DAYS || 1);
  const expires = new Date(Date.now() + days*24*60*60*1000).toISOString();
  db.prepare('INSERT INTO refresh_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)')
    .run(hashToken(refreshToken), user.id, expires);
  audit({subject:user.username, endpoint:req.path, deviceId, decision:'allow', reason:'Login berhasil; kredensial dan device valid'});
  res.json({ accessToken, refreshToken, tokenType:'Bearer', expiresInMinutes:Number(process.env.ACCESS_TOKEN_MINUTES || 10),
    user:{username:user.username, role:user.role, displayName:user.display_name, nim:user.nim} });
});

app.post('/auth/refresh', (req,res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return fail(res, 400, 'refreshToken wajib diisi');
  const row = db.prepare(`SELECT rt.*,u.username,u.role,u.display_name,u.nim FROM refresh_tokens rt JOIN users u ON u.id=rt.user_id WHERE rt.token_hash=?`)
    .get(hashToken(refreshToken));
  if (!row || row.revoked_at || new Date(row.expires_at) <= new Date()) {
    audit({subject:row?.username || 'unknown', endpoint:req.path, decision:'deny', reason:'Refresh token tidak valid, kedaluwarsa, atau dicabut'});
    return fail(res, 401, 'Refresh token tidak valid, kedaluwarsa, atau sudah dicabut');
  }
  const user = {id:row.user_id, username:row.username, role:row.role};
  res.json({ accessToken:signAccessToken(user), expiresInMinutes:Number(process.env.ACCESS_TOKEN_MINUTES || 10) });
});

app.post('/auth/logout', (req,res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return fail(res, 400, 'refreshToken wajib diisi');
  const result = db.prepare('UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL')
    .run(new Date().toISOString(), hashToken(refreshToken));
  audit({subject:'refresh-token-holder', endpoint:req.path, decision:result.changes?'allow':'deny',
    reason:result.changes?'Refresh token dicabut':'Token tidak ditemukan atau sudah dicabut'});
  if (!result.changes) return fail(res, 401, 'Refresh token tidak ditemukan atau sudah dicabut');
  res.json({message:'Logout berhasil; refresh token dicabut'});
});

app.post('/auth/service', (req,res) => {
  const { clientId, clientSecret } = req.body || {};
  if (
  clientId !== process.env.SERVICE_CLIENT_ID ||
  clientSecret !== process.env.SERVICE_CLIENT_SECRET
  ) 
  audit({subject:clientId, endpoint:req.path, decision:'allow', reason:'Kredensial service valid'});
  res.json({accessToken:signServiceToken(), tokenType:'Bearer', expiresInMinutes:Number(process.env.SERVICE_TOKEN_MINUTES || 5)});
});

async function proxy(req,res,targetBase) {
  const token = bearer(req);
  if (!token) {
    audit({subject:'anonymous', endpoint:req.path, deviceId:req.header('X-Device-ID'), decision:'deny', reason:'Access token tidak ada'});
    return fail(res,401,'Access token wajib diisi');
  }
  let claims;
  try { claims = verifyToken(token); }
  catch { audit({subject:'unknown',endpoint:req.path,deviceId:req.header('X-Device-ID'),decision:'deny',reason:'Token tidak valid atau kedaluwarsa'}); return fail(res,401,'Token tidak valid atau kedaluwarsa'); }

  const isService = claims.role === 'service';
  const deviceId = req.header('X-Device-ID');
  if (!isService) {
    if (!deviceRegistered(claims.sub, deviceId)) {
      audit({subject:claims.username || claims.sub,endpoint:req.path,deviceId,decision:'deny',reason:'Device tidak terdaftar'});
      return fail(res,403,'Device tidak terdaftar untuk user ini');
    }
    const result = decide({user:claims,method:req.method,path:req.path,params:req.params,body:req.body});
    if (!result.allow) {
      audit({subject:claims.username || claims.sub,endpoint:req.path,deviceId,decision:'deny',reason:result.reason});
      return fail(res,403,result.reason);
    }
    audit({subject:claims.username || claims.sub,endpoint:req.path,deviceId,decision:'allow',reason:result.reason});
  } else {
    if (!(req.path === '/transkrip/sinkron' && req.method === 'POST')) {
      audit({subject:claims.sub,endpoint:req.path,decision:'deny',reason:'Token service hanya untuk sinkronisasi transkrip'});
      return fail(res,403,'Token service tidak diizinkan untuk endpoint ini');
    }
    audit({subject:claims.sub,endpoint:req.path,decision:'allow',reason:'Token service valid untuk sinkronisasi'});
  }

  try {
    const headers = {'Content-Type':'application/json','Authorization':`Bearer ${token}`,'X-Gateway-Secret':GATEWAY_SECRET};
    if (deviceId) headers['X-Device-ID'] = deviceId;
    const upstream = await fetch(targetBase + req.originalUrl, {
      method:req.method, headers,
      body:['GET','HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body || {})
    });
    const data = await upstream.text();
    res.status(upstream.status);
    res.type(upstream.headers.get('content-type') || 'application/json');
    return res.send(data);
  } catch (err) {
    return fail(res,502,'Service tidak dapat dihubungi. Pastikan kedua service sudah berjalan.');
  }
}
app.all('/nilai', (req,res)=>proxy(req,res,NILAI));
app.all('/nilai/*', (req,res)=>proxy(req,res,NILAI));
app.all('/kelas/*', (req,res)=>proxy(req,res,NILAI));
app.all('/transkrip/*', (req,res)=>proxy(req,res,TRANSKRIP));


app.get('/admin/audit-logs', (req, res) => {
  const token = bearer(req);
  const deviceId = req.header('X-Device-ID');

  // 1. Memastikan access token tersedia
  if (!token) {
    audit({
      subject: 'anonymous',
      endpoint: req.path,
      deviceId,
      decision: 'deny',
      reason: 'Access token tidak ada'
    });

    return fail(res, 401, 'Access token wajib diisi');
  }

  // 2. Memverifikasi JWT
  let claims;

  try {
    claims = verifyToken(token);
  } catch {
    audit({
      subject: 'unknown',
      endpoint: req.path,
      deviceId,
      decision: 'deny',
      reason: 'Token tidak valid atau kedaluwarsa'
    });

    return fail(res, 401, 'Token tidak valid atau kedaluwarsa');
  }

  // 3. Memastikan pengguna merupakan admin
  if (claims.role !== 'admin') {
    audit({
      subject: claims.username || claims.sub,
      endpoint: req.path,
      deviceId,
      decision: 'deny',
      reason: 'Hanya admin boleh melihat audit log'
    });

    return fail(res, 403, 'Hanya admin boleh melihat audit log');
  }

  // 4. Memastikan perangkat admin terdaftar
  if (!deviceRegistered(claims.sub, deviceId)) {
    audit({
      subject: claims.username || claims.sub,
      endpoint: req.path,
      deviceId,
      decision: 'deny',
      reason: 'Device tidak terdaftar'
    });

    return fail(res, 403, 'Device tidak terdaftar untuk user ini');
  }

  // 5. Mencatat akses admin yang berhasil
  audit({
    subject: claims.username || claims.sub,
    endpoint: req.path,
    deviceId,
    decision: 'allow',
    reason: 'Admin berhasil mengakses audit log'
  });

  // 6. Mengambil riwayat aktivitas
  const logs = db.prepare(
    'SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200'
  ).all();

  return res.json(logs);
});


app.listen(PORT,()=>console.log(`API Gateway berjalan di http://localhost:${PORT}`));
