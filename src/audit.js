const db = require('./db');
function audit({ subject = 'anonymous', endpoint, deviceId = null, decision, reason }) {
  db.prepare(`INSERT INTO audit_logs(created_at, subject, endpoint, device_id, decision, reason)
    VALUES (?, ?, ?, ?, ?, ?)`).run(new Date().toISOString(), String(subject), endpoint,
    deviceId, decision, reason);
}
module.exports = { audit };
