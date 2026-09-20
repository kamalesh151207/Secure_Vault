const express = require('express');
const router = express.Router();
const { authenticateJwt } = require('../middleware/authMiddleware');
const { getDb } = require('../db/database');
const { decryptField } = require('../crypto/encryption');
const AuditLogger = require('../services/auditLogger');

/**
 * GET /data
 * Returns user profile and decrypted PII on-the-fly using parameterized query
 */
router.get('/', authenticateJwt, async (req, res) => {
  const userId = req.user.id;
  const db = getDb();
  const sourceIp = req.ip || '127.0.0.1';

  try {
    // Parameterized SQL query
    const queryResult = await db.query(
      'SELECT id, username, encrypted_email, created_at FROM users WHERE id = $1',
      [userId]
    );

    if (!queryResult.rows || queryResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User Not Found',
        message: 'No record matching authenticated user ID.'
      });
    }

    const userRecord = queryResult.rows[0];

    // Decrypt email on-the-fly
    let decryptedEmail = null;
    let encryptionMeta = null;

    try {
      decryptedEmail = decryptField(userRecord.encrypted_email);
      const parts = userRecord.encrypted_email.split(':');
      if (parts.length === 3) {
        encryptionMeta = {
          iv: parts[0],
          authTag: parts[1],
          ciphertext: parts[2],
          algorithm: 'AES-256-GCM',
          keyManagement: 'KMS Master Key Envelope Encryption'
        };
      }
    } catch (e) {
      decryptedEmail = 'Decryption error or unencrypted legacy data';
    }

    // Log query execution
    await AuditLogger.logQuery({
      userId,
      queryText: `FETCH USER DATA id=${userId} (Parameterized prepared statement)`,
      isMalicious: false,
      sourceIp
    });

    res.json({
      message: 'User data fetched and decrypted on-the-fly successfully.',
      data: {
        id: userRecord.id,
        username: userRecord.username,
        email: decryptedEmail,
        createdAt: userRecord.created_at,
        encryptionStatus: {
          encryptedFormatStored: userRecord.encrypted_email,
          meta: encryptionMeta
        }
      }
    });
  } catch (err) {
    console.error('[GET /data Error]', err);
    res.status(500).json({
      error: 'Data Fetch Failed',
      message: err.message
    });
  }
});

module.exports = router;
