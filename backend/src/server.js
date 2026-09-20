const app = require('./app');
const config = require('./config/env');

const PORT = config.port;

app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` 🛡️  SecureVault AntiGravity Backend Running locally `);
  console.log(` 🌐 URL: http://localhost:${PORT}`);
  console.log(` 🔒 Security: Double-Layer (WAF Regex + Prepared Statements)`);
  console.log(` 🔑 Crypto: AES-256-GCM Envelope Encryption`);
  console.log(` 🎟️  Capability: HMAC-SHA256 (5 min validity)`);
  console.log(`=======================================================`);
});
