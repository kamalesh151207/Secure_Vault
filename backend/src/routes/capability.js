const express = require('express');
const router = express.Router();
const { authenticateJwt } = require('../middleware/authMiddleware');
const { generateCapabilityToken } = require('../capability/capabilityToken');
const AuditLogger = require('../services/auditLogger');

/**
 * POST /capability/generate
 * Issues a 5-minute valid HMAC-SHA256 signed Capability Token granting temporary write & pen-test access
 */
router.post('/generate', authenticateJwt, async (req, res) => {
  const userId = req.user.id;
  const sourceIp = req.ip || '127.0.0.1';

  try {
    const capabilityResult = generateCapabilityToken(userId, 'write:pentest');

    await AuditLogger.logQuery({
      userId,
      queryText: `GENERATE CAPABILITY TOKEN userId=${userId} expiresAt=${capabilityResult.expiresAt}`,
      isMalicious: false,
      sourceIp
    });

    res.json({
      message: 'Capability Code generated successfully. Valid for 5 minutes (300 seconds).',
      capabilityCode: capabilityResult.token,
      expiresAt: capabilityResult.expiresAt,
      expiresInSeconds: capabilityResult.expiresInSeconds,
      scope: 'write:pentest',
      usage: 'Include as header "X-Capability-Token: <token>" to execute INSERT/UPDATE/DELETE or pen-test queries.'
    });
  } catch (err) {
    console.error('[Capability Generate Error]', err);
    res.status(500).json({
      error: 'Generation Failed',
      message: err.message
    });
  }
});

module.exports = router;
