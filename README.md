# Zero Trust Security — Sistem Nilai

Implementasi praktikum keamanan informasi menggunakan Node.js, Express, SQLite, dan JSON Web Token (JWT).

## 1. Persiapan

1. Install Node.js LTS (disarankan Node.js versi 20 atau 22).
2. Salin `.env.example` menjadi `.env`.
3. Ganti `JWT_SECRET` dan `GATEWAY_SECRET` dengan nilai acak yang kuat dan berbeda.
4. Buka terminal pada folder project, kemudian jalankan:

   ```powershell
   npm install
   npm run seed
   ```

5. Buka tiga terminal VS Code dan jalankan masing-masing service:

   **Terminal 1 — API Gateway**
   ```powershell
   npm run gateway
   ```

   **Terminal 2 — Service Nilai**
   ```powershell
   npm run nilai
   ```

   **Terminal 3 — Service Transkrip**
   ```powershell
   npm run transkrip
   ```

6. Seluruh permintaan pengguna ke layanan aplikasi dikirim melalui API Gateway:

   `http://localhost:3000`

   Catatan: Pada Windows PowerShell, gunakan `npm.cmd` apabila perintah `npm` terhalang kebijakan eksekusi script.

## 2. Akun Demo

Password seluruh akun demo: `Demo123!`

| Role | Username | Device ID |
|---|---|---|
| Admin | admin1 | DEV-ADMIN-01 |
| Dosen | dosen1 | DEV-DOSEN-01 |
| Dosen | dosen2 | DEV-DOSEN-02 |
| Mahasiswa | mhs1 | DEV-MHS-01 |
| Mahasiswa | mhs2 | DEV-MHS-02 |
| Mahasiswa | mhs3 | DEV-MHS-03 |

## 3. Arsitektur Sistem

Aplikasi menerapkan pendekatan Zero Trust dengan prinsip *Never Trust, Always Verify*. Setiap permintaan akses terhadap sumber daya yang dilindungi harus melalui proses autentikasi dan pemeriksaan kebijakan sebelum diteruskan ke layanan tujuan.

Komponen utama sistem:

| Komponen | Port | Fungsi |
|---|---:|---|
| API Gateway (PEP) | 3000 | Menerima permintaan, memeriksa token, perangkat, dan kebijakan akses |
| Service Nilai | 3001 | Mengelola nilai, perubahan nilai, dan finalisasi kelas |
| Service Transkrip | 3002 | Menyimpan dan menyediakan data transkrip mahasiswa |

API Gateway berperan sebagai Policy Enforcement Point (PEP), sedangkan pengambilan keputusan kebijakan dilakukan melalui modul Policy Engine pada `src/policy.js`.

Ketiga komponen menggunakan database SQLite bersama.

## 4. Mekanisme Keamanan

Implementasi keamanan pada aplikasi meliputi:

1. **Authentication** — Pengguna melakukan login menggunakan username dan password yang diverifikasi menggunakan bcrypt.
2. **Access Token** — JWT digunakan untuk autentikasi permintaan pengguna dengan masa berlaku default 10 menit.
3. **Refresh Token** — Digunakan untuk memperoleh access token baru, memiliki masa berlaku default satu hari, dan dapat dicabut melalui proses logout. Token disimpan dalam bentuk hash SHA-256.
4. **Device Verification** — Permintaan login dan akses terhadap sumber daya yang dilindungi memerlukan `X-Device-ID` yang telah terdaftar.
5. **Role-Based Access Control** — Hak akses dibedakan berdasarkan peran mahasiswa, dosen, dan admin.
6. **Service Authentication** — Service Nilai memperoleh service token dari API Gateway untuk melakukan sinkronisasi transkrip. Masa berlaku default service token adalah lima menit.
7. **Gateway Verification** — Service Nilai dan Service Transkrip melakukan pemeriksaan Gateway Secret dan JWT secara mandiri.
8. **Audit Logging** — Aktivitas akses dicatat berdasarkan waktu, identitas pengguna atau layanan, endpoint, identitas perangkat jika tersedia, keputusan ALLOW atau DENY, serta alasan keputusan.

## 5. Kebijakan Akses

| Role | Hak akses |
|---|---|
| Mahasiswa | Melihat nilai dan transkrip miliknya sendiri |
| Dosen | Melihat, mengubah, dan memfinalisasi nilai pada kelas yang diampu |
| Admin | Melihat seluruh transkrip mahasiswa |
| Service Nilai | Melakukan sinkronisasi nilai ke Service Transkrip menggunakan service token |

Perubahan dan finalisasi nilai dibatasi pada pukul 07.00–21.00 WIB sesuai konfigurasi waktu sistem.

Nilai yang sudah difinalisasi tidak dapat diubah kembali melalui endpoint perubahan nilai.

## 6. Daftar Endpoint API

Seluruh endpoint aplikasi diakses melalui API Gateway `http://localhost:3000`.

| Method | Endpoint | Fungsi |
|---|---|---|
| POST | `/auth/login` | Login pengguna |
| POST | `/auth/refresh` | Memperbarui access token |
| POST | `/auth/logout` | Mencabut refresh token |
| POST | `/auth/service` | Autentikasi layanan untuk memperoleh service token |
| GET | `/nilai` | Melihat nilai sesuai kewenangan pengguna |
| PUT | `/nilai/:id` | Mengubah nilai oleh dosen pengampu |
| POST | `/kelas/:id/finalisasi` | Finalisasi nilai kelas |
| GET | `/transkrip/:nim` | Melihat transkrip mahasiswa |
| POST | `/transkrip/sinkron` | Sinkronisasi transkrip menggunakan service token |
| GET | `/admin/audit-logs` | Melihat catatan aktivitas keamanan oleh admin |

Catatan:
- `/auth/service` digunakan untuk autentikasi layanan, bukan login pengguna biasa.
- `/transkrip/sinkron` hanya boleh diakses menggunakan service token yang valid.
- Endpoint layanan internal tidak boleh diakses secara langsung tanpa Gateway Secret dan token yang sesuai.

## 7. Skenario Pengujian

Pengujian aplikasi dilakukan menggunakan Postman dengan skenario berikut:

1. Login menggunakan akun dan perangkat yang terdaftar.
2. Login dengan password yang salah.
3. Mengakses endpoint tanpa access token.
4. Mengakses endpoint menggunakan token tidak valid.
5. Mengakses menggunakan perangkat yang tidak terdaftar.
6. Mahasiswa melihat transkrip mahasiswa lain.
7. Mahasiswa melihat transkrip miliknya sendiri.
8. Admin melihat transkrip mahasiswa lain.
9. Dosen mengakses nilai kelas yang diampu.
10. Dosen bukan pengampu mencoba mengubah nilai kelas lain.
11. Dosen mengubah nilai kelas yang diampu.
12. Finalisasi nilai dan sinkronisasi ke Service Transkrip.
13. Mengubah nilai yang sudah difinalisasi.
14. Memperbarui access token menggunakan refresh token.
15. Menguji pencabutan refresh token melalui logout.
16. Memeriksa pencatatan aktivitas melalui audit log.

## 8. Struktur Project

```text
praktikum1/
├── gateway/
│   └── server.js
├── services/
│   ├── nilai.js
│   └── transkrip.js
├── src/
│   ├── db.js
│   ├── policy.js
│   ├── security.js
│   └── audit.js
├── scripts/
│   └── seed.js
├── .env.example
├── .gitignore
├── package.json
└── README.md
```

File `.env` dan database lokal tidak perlu diunggah apabila mengandung konfigurasi atau data pribadi. Gunakan `.env.example` sebagai contoh konfigurasi.

## 9. Catatan Keamanan

Aplikasi ini merupakan implementasi praktikum untuk demonstrasi konsep Zero Trust pada lingkungan lokal, bukan sistem yang siap digunakan di lingkungan produksi.

Untuk penerapan produksi diperlukan HTTPS, pengelolaan secret yang aman, rate limiting, pemantauan keamanan, serta hardening tambahan.