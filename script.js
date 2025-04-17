const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const ENCRYPTION_KEY = crypto.randomBytes(32);
const IV = crypto.randomBytes(16); 

const encrypt = (payload, secret) => {
  const token = jwt.sign(payload, secret, { expiresIn: '1h' });

  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return { encryptedToken: encrypted, iv: IV.toString('hex') };
};

module.exports = encrypt;