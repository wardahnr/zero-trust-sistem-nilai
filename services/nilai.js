
require('dotenv').config();

const express = require('express');
const db = require('../src/db');
const { verifyToken, GATEWAY_SECRET } = require('../src/security');

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT_NILAI || 3001);
const GATEWAY_PORT = Number(process.env.PORT_GATEWAY || 3000);
const GATEWAY_URL = `http://127.0.0.1:${GATEWAY_PORT}`;

// Memeriksa rahasia Gateway dan token akses pada setiap permintaan.
function protect(req, res, next) {
  if (req.header('X-Gateway-Secret') !== GATEWAY_SECRET) {
    return res.status(403).json({
      error: 'Gateway secret tidak valid; akses langsung ditolak'
    });
  }

  const auth = req.header('Authorization') || '';

  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Token wajib diisi'
    });
  }

  try {
    req.claims = verifyToken(auth.slice(7));
  } catch {
    return res.status(401).json({
      error: 'Token tidak valid atau kedaluwarsa'
    });
  }

  next();
}

// Meminta service token kepada API Gateway.
// Service token tidak dibuat sendiri oleh Service Nilai.
async function requestServiceToken() {
  const response = await fetch(`${GATEWAY_URL}/auth/service`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      clientId: process.env.SERVICE_CLIENT_ID || 'service-nilai',
      clientSecret:
        process.env.SERVICE_CLIENT_SECRET || 'secret-service-nilai'
    })
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || !data.accessToken) {
    throw new Error(
      data.error || data.message || 'Gagal memperoleh service token'
    );
  }

  return data.accessToken;
}

// Endpoint pemeriksaan kondisi layanan.
app.get('/health', (req, res) => {
  res.json({
    service: 'nilai',
    status: 'ok'
  });
});

// Endpoint berikutnya wajib melewati pemeriksaan Gateway.
app.use(protect);

// Mengambil nilai sesuai dengan identitas dan kewenangan pengguna.
app.get('/nilai', (req, res) => {
  const claims = req.claims;
  let rows;

  if (claims.role === 'mahasiswa') {
    rows = db.prepare(`
      SELECT
        g.id,
        g.score,
        c.id AS class_id,
        c.class_name,
        c.course_name,
        c.is_final
      FROM grades g
      JOIN classes c ON c.id = g.class_id
      WHERE g.student_id = ?
    `).all(Number(claims.sub));

  } else if (claims.role === 'dosen') {
    rows = db.prepare(`
      SELECT
        g.id,
        g.score,
        g.student_id,
        c.id AS class_id,
        c.class_name,
        c.course_name,
        c.is_final
      FROM grades g
      JOIN classes c ON c.id = g.class_id
      WHERE c.lecturer_id = ?
    `).all(Number(claims.sub));

  } else {
    return res.status(403).json({
      error: 'Role tidak boleh melihat nilai'
    });
  }

  res.json(rows);
});

// Mengubah nilai.
// Hanya dosen pengampu yang boleh mengubah nilai yang belum final.
// Pemeriksaan jam akses juga dilakukan oleh kebijakan pada Gateway.
app.put('/nilai/:id', (req, res) => {
  if (req.claims.role !== 'dosen') {
    return res.status(403).json({
      error: 'Hanya dosen yang boleh mengubah nilai'
    });
  }

  const score = Number(req.body.score);

  if (!Number.isFinite(score) || score < 0 || score > 100) {
    return res.status(400).json({
      error: 'score harus angka 0 sampai 100'
    });
  }

  const grade = db.prepare(`
    SELECT
      g.id,
      c.lecturer_id,
      c.is_final
    FROM grades g
    JOIN classes c ON c.id = g.class_id
    WHERE g.id = ?
  `).get(Number(req.params.id));

  if (!grade) {
    return res.status(404).json({
      error: 'Nilai tidak ditemukan'
    });
  }

  if (grade.lecturer_id !== Number(req.claims.sub)) {
    return res.status(403).json({
      error: 'Dosen bukan pengampu kelas ini'
    });
  }

  if (grade.is_final) {
    return res.status(409).json({
      error: 'Nilai sudah difinalisasi'
    });
  }

  db.prepare('UPDATE grades SET score = ? WHERE id = ?')
    .run(score, grade.id);

  res.json({
    message: 'Nilai berhasil diubah',
    gradeId: grade.id,
    score
  });
});

// Finalisasi nilai dan sinkronisasi ke Service Transkrip.
app.post('/kelas/:id/finalisasi', async (req, res) => {
  if (req.claims.role !== 'dosen') {
    return res.status(403).json({
      error: 'Hanya dosen yang boleh finalisasi nilai'
    });
  }

  const classId = Number(req.params.id);

  const klass = db.prepare(
    'SELECT * FROM classes WHERE id = ?'
  ).get(classId);

  if (!klass) {
    return res.status(404).json({
      error: 'Kelas tidak ditemukan'
    });
  }

  if (klass.lecturer_id !== Number(req.claims.sub)) {
    return res.status(403).json({
      error: 'Dosen bukan pengampu kelas ini'
    });
  }

  if (klass.is_final) {
    return res.status(409).json({
      error: 'Kelas sudah difinalisasi'
    });
  }

  // Langkah 1: Meminta service token dari API Gateway.
  // Jika gagal, kelas belum difinalisasi.
  let serviceToken;

  try {
    serviceToken = await requestServiceToken();
  } catch (error) {
    return res.status(502).json({
      error: 'Gagal memperoleh service token dari Gateway',
      detail: error.message
    });
  }

  // Langkah 2: Menandai kelas sebagai final.
  db.prepare(
  'UPDATE classes SET is_final = 0 WHERE id = ?'
  ).run(klass.id);

  // Langkah 3: Meminta Gateway meneruskan sinkronisasi
  // menggunakan service token, bukan token pengguna.
  try {
    const upstream = await fetch(
      `${GATEWAY_URL}/transkrip/sinkron`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${serviceToken}`
        },
        body: JSON.stringify({
          classId: klass.id
        })
      }
    );

    const result = await upstream.json().catch(() => ({}));

    if (!upstream.ok) {
      return res.status(502).json({
        message:
          'Nilai difinalisasi, tetapi sinkronisasi transkrip gagal',
        detail: result
      });
    }

    return res.json({
      message: 'Kelas berhasil difinalisasi dan transkrip disinkronkan',
      classId: klass.id,
      transcriptSync: result
    });

  } catch (error) {
    return res.status(502).json({
      message:
        'Nilai difinalisasi, tetapi Service Transkrip tidak dapat dihubungi',
      detail: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Service Nilai berjalan di http://localhost:${PORT}`);
});
