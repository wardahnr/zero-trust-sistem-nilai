require('dotenv').config();
const express = require('express');
const db = require('../src/db');
const { verifyToken, GATEWAY_SECRET } = require('../src/security');
const app=express(); app.use(express.json());
const PORT=Number(process.env.PORT_TRANSKRIP||3002);

function protect(req,res,next) {
  if(req.header('X-Gateway-Secret')!==GATEWAY_SECRET) return res.status(403).json({error:'Gateway secret tidak valid; akses langsung ditolak'});
  const auth=req.header('Authorization')||'';
  if(!auth.startsWith('Bearer ')) return res.status(401).json({error:'Token wajib diisi'});
  try { req.claims=verifyToken(auth.slice(7)); }
  catch { return res.status(401).json({error:'Token tidak valid atau kedaluwarsa'}); }
  next();
}
app.get('/health',(req,res)=>res.json({service:'transkrip',status:'ok'}));
app.use(protect);

app.get('/transkrip/:nim',(req,res)=>{
  const c=req.claims;
  if(c.role==='mahasiswa') {
    const user=db.prepare('SELECT nim FROM users WHERE id=?').get(Number(c.sub));
    if(!user||user.nim!==req.params.nim) return res.status(403).json({error:'Mahasiswa hanya boleh melihat transkrip miliknya'});
  } else if(c.role!=='admin') return res.status(403).json({error:'Role tidak boleh melihat transkrip'});
  const rows=db.prepare(`SELECT t.course_name,t.score,t.synced_at,c.class_name
    FROM transcripts t JOIN users u ON u.id=t.student_id JOIN classes c ON c.id=t.class_id
    WHERE u.nim=? ORDER BY t.id`).all(req.params.nim);
  res.json({nim:req.params.nim,transcripts:rows});
});

app.post('/transkrip/sinkron',(req,res)=>{
  if(req.claims.role!=='service'||req.claims.sub!=='service-nilai') return res.status(403).json({error:'Hanya token service-nilai yang boleh sinkronisasi'});
  const classId=Number(req.body.classId);
  const klass=db.prepare('SELECT * FROM classes WHERE id=?').get(classId);
  if(!klass||!klass.is_final) return res.status(400).json({error:'Kelas tidak ditemukan atau belum difinalisasi'});
  const rows=db.prepare('SELECT student_id,score FROM grades WHERE class_id=?').all(classId);
  const upsert=db.prepare(`INSERT INTO transcripts(student_id,class_id,course_name,score,synced_at)
    VALUES(?,?,?,?,?) ON CONFLICT(student_id,class_id) DO UPDATE SET
    course_name=excluded.course_name,score=excluded.score,synced_at=excluded.synced_at`);
  const now=new Date().toISOString();
  const tx=db.transaction(()=>rows.forEach(row=>upsert.run(row.student_id,classId,klass.course_name,row.score,now)));
  tx();
  res.json({message:'Sinkronisasi transkrip berhasil',classId,records:rows.length});
});
app.listen(PORT,()=>console.log(`Service Transkrip berjalan di http://localhost:${PORT}`));
