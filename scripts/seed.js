require('dotenv').config();
const bcrypt = require('bcryptjs');
const db = require('../src/db');

const seed = db.transaction(() => {
  db.exec('DELETE FROM audit_logs; DELETE FROM refresh_tokens; DELETE FROM transcripts; DELETE FROM grades; DELETE FROM classes; DELETE FROM devices; DELETE FROM users;');
  const insertUser = db.prepare('INSERT INTO users(username,password_hash,role,display_name,nim) VALUES(?,?,?,?,?)');
  const password = bcrypt.hashSync('Demo123!', 10);
  const users = {};
  users.admin1 = insertUser.run('admin1', password, 'admin', 'Admin Sistem', null).lastInsertRowid;
  users.dosen1 = insertUser.run('dosen1', password, 'dosen', 'Dosen Satu', null).lastInsertRowid;
  users.dosen2 = insertUser.run('dosen2', password, 'dosen', 'Dosen Dua', null).lastInsertRowid;
  users.mhs1 = insertUser.run('mhs1', password, 'mahasiswa', 'Mahasiswa Satu', '247006111101').lastInsertRowid;
  users.mhs2 = insertUser.run('mhs2', password, 'mahasiswa', 'Mahasiswa Dua', '247006111102').lastInsertRowid;
  users.mhs3 = insertUser.run('mhs3', password, 'mahasiswa', 'Mahasiswa Tiga', '247006111103').lastInsertRowid;

  const device = db.prepare('INSERT INTO devices(user_id,device_id) VALUES(?,?)');
  Object.entries({admin1:'DEV-ADMIN-01', dosen1:'DEV-DOSEN-01', dosen2:'DEV-DOSEN-02',
    mhs1:'DEV-MHS-01', mhs2:'DEV-MHS-02', mhs3:'DEV-MHS-03'})
    .forEach(([username, id]) => device.run(users[username], id));

  const klass = db.prepare('INSERT INTO classes(class_name,course_name,lecturer_id) VALUES(?,?,?)');
  const c1 = klass.run('IF-A', 'Keamanan Informasi', users.dosen1).lastInsertRowid;
  const c2 = klass.run('IF-B', 'Keamanan Informasi', users.dosen2).lastInsertRowid;
  const grade = db.prepare('INSERT INTO grades(class_id,student_id,score) VALUES(?,?,?)');
  grade.run(c1, users.mhs1, 85);
  grade.run(c1, users.mhs2, 90);
  grade.run(c2, users.mhs3, 88);
});
seed();
console.log('Seed selesai. Password semua akun demo: Demo123!');
console.log('Kelas: ID 1 diampu dosen1; ID 2 diampu dosen2. Nilai: ID 1, 2, 3.');
db.close();
