const db = require('./db');

function isWithinAccessHours(date = new Date()) {
  // Mengikuti zona waktu yang dikonfigurasi; default Asia/Jakarta.
  const hour = Number(new Intl.DateTimeFormat('en-GB', {
    timeZone: process.env.TIMEZONE || 'Asia/Jakarta',
    hour: '2-digit', hourCycle: 'h23'
  }).format(date));
  const start = Number(process.env.ACCESS_START_HOUR || 7);
  const end = Number(process.env.ACCESS_END_HOUR || 21);
  return hour >= start && hour < end;
}

function deviceRegistered(userId, deviceId) {
  if (!deviceId) return false;
  return !!db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?')
    .get(Number(userId), deviceId);
}

function decide({ user, method, path, params = {}, body = {} }) {
  const role = user.role;
  if (path === '/nilai' && method === 'GET') {
    if (role === 'mahasiswa' || role === 'dosen') return { allow: true, reason: 'Role boleh membaca nilai; kepemilikan diperiksa service' };
  }
  if (/^\/nilai\/\d+$/.test(path) && method === 'PUT') {
    if (role !== 'dosen') return { allow: false, reason: 'Hanya dosen yang boleh mengubah nilai' };
    if (!isWithinAccessHours()) return { allow: false, reason: 'Di luar jam akses 07.00-21.00 WIB' };
    const grade = db.prepare(`SELECT g.id, c.lecturer_id, c.is_final FROM grades g JOIN classes c ON c.id=g.class_id WHERE g.id=?`).get(Number(path.split('/')[2]));
    if (!grade) return { allow: false, reason: 'Nilai tidak ditemukan' };
    if (grade.lecturer_id !== Number(user.sub)) return { allow: false, reason: 'Dosen bukan pengampu kelas ini' };
    if (grade.is_final) return { allow: false, reason: 'Nilai sudah difinalisasi' };
    return { allow: true, reason: 'Dosen pengampu, nilai belum final, dan jam akses valid' };
  }
  const finalizeMatch = path.match(/^\/kelas\/(\d+)\/finalisasi$/);
  if (finalizeMatch && method === 'POST') {
    if (role !== 'dosen') return { allow: false, reason: 'Hanya dosen yang boleh finalisasi nilai' };
    if (!isWithinAccessHours()) return { allow: false, reason: 'Di luar jam akses 07.00-21.00 WIB' };
    const klass = db.prepare('SELECT id, lecturer_id, is_final FROM classes WHERE id=?').get(Number(finalizeMatch[1]));
    if (!klass) return { allow: false, reason: 'Kelas tidak ditemukan' };
    if (klass.lecturer_id !== Number(user.sub)) return { allow: false, reason: 'Dosen bukan pengampu kelas ini' };
    if (klass.is_final) return { allow: false, reason: 'Kelas sudah difinalisasi' };
    return { allow: true, reason: 'Dosen pengampu dan jam akses valid' };
  }
  const transcriptMatch = path.match(/^\/transkrip\/([^/]+)$/);
  if (transcriptMatch && method === 'GET') {
    if (role === 'admin') return { allow: true, reason: 'Admin boleh melihat semua transkrip' };
    if (role === 'mahasiswa') {
      const student = db.prepare('SELECT nim FROM users WHERE id=?').get(Number(user.sub));
      if (student && student.nim === decodeURIComponent(transcriptMatch[1])) return { allow: true, reason: 'Mahasiswa hanya melihat transkrip miliknya' };
      return { allow: false, reason: 'Mahasiswa hanya boleh melihat transkrip miliknya sendiri' };
    }
  }
  if (path === '/transkrip/sinkron' && method === 'POST') {
    return { allow: false, reason: 'Endpoint sinkronisasi hanya untuk token service, bukan token user' };
  }
  return { allow: false, reason: 'Tidak ada kebijakan yang mengizinkan request ini' };
}
module.exports = { decide, deviceRegistered, isWithinAccessHours };
