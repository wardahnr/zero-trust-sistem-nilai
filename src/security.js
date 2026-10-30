require('dotenv').config();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dev-gateway-secret-change-me';

function signAccessToken(user) {
  return jwt.sign({ sub: String(user.id), role: user.role, username: user.username },
    JWT_SECRET, { expiresIn: `${Number(process.env.ACCESS_TOKEN_MINUTES || 10)}m` });
}
function signServiceToken() {
  return jwt.sign({ sub: 'service-nilai', role: 'service' }, JWT_SECRET,
    { expiresIn: `${Number(process.env.SERVICE_TOKEN_MINUTES || 5)}m` });
}
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
module.exports = { JWT_SECRET, GATEWAY_SECRET, signAccessToken, signServiceToken, verifyToken, hashToken };
