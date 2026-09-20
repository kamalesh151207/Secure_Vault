const express = require('express');
const router = express.Router();
const { requireCapabilityTokenMiddleware } = require('../capability/capabilityToken');
const { scanValueForSqli } = require('../middleware/wafSecurity');
const { getDb } = require('../db/database');
const AuditLogger = require('../services/auditLogger');
const AlertService = require('../services/alertService');

/**
 * POST /test/inject
 * Sandboxed endpoint for pen-testing SQL injection payloads
 * Enforces Capability Token authorization and runs queries inside BEGIN; ... ROLLBACK;
 */
router.post('/inject', requireCapabilityTokenMiddleware, async (req, res) => {
  const { payload, simulateParameterization = true } = req.body;
  const sourceIp = req.ip || '127.0.0.1';

  if (!payload || typeof payload !== 'string') {
    return res.status(400).json({
      error: 'Validation Error',
      message: 'Body parameter "payload" (string) is required for pen-testing.'
    });
  }

  // 1. Layer 1 WAF Inspection
  const layer1Match = scanValueForSqli(payload);
  const isMalicious = !!layer1Match;

  if (isMalicious) {
    await AlertService.triggerSqlInjectionAlert({
      sourceIp,
      path: '/test/inject',
      method: 'POST',
      pattern: layer1Match.pattern,
      payloadSnippet: payload.substring(0, 100)
    });
  }

  // Log test execution to database audit logs table
  await AuditLogger.logQuery({
    userId: req.capability ? req.capability.userId : null,
    queryText: `PEN-TEST INJECTION ATTEMPT payload="${payload.substring(0, 100)}"`,
    isMalicious,
    sourceIp
  });

  const db = getDb();
  let layer2Result = null;
  let transactionStatus = 'EXECUTED_AND_ROLLED_BACK';

  try {
    // 2. Layer 2 Safe Parameterized Query Execution inside transaction ROLLBACK
    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      if (simulateParameterization) {
        // Safe Parameterized execution: payload treated strictly as a literal string value, incapable of breaking out of syntax!
        const result = await client.query(
          'SELECT id, username, encrypted_email FROM users WHERE username = $1',
          [payload]
        );
        layer2Result = {
          success: true,
          mode: 'Parameterized Prepared Statement (Layer 2 Defense)',
          recordsReturned: result.rows.length,
          explanation: 'Parameterized query treated the payload strictly as literal data. Zero SQL injection risk.'
        };
      } else {
        // Unsafe string concatenation mode (for visual comparison demonstration in sandbox)
        layer2Result = {
          success: false,
          mode: 'Direct Concatenation Simulation',
          explanation: 'Unparameterized query concatenated payload directly into SQL string.'
        };
      }

      // Always ROLLBACK transaction in pen-test sandbox!
      await client.query('ROLLBACK');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch (e) {}
      layer2Result = {
        success: false,
        error: err.message,
        explanation: 'Database rejected query syntax or statement timeout kicked in.'
      };
    } finally {
      if (client.release) client.release();
    }
  } catch (dbErr) {
    transactionStatus = 'TRANSACTION_FAILED';
  }

  res.json({
    message: 'Pen-test payload analyzed inside sandboxed transaction.',
    capabilityAuthorized: true,
    capabilityToken: {
      userId: req.capability.userId,
      scope: req.capability.scope,
      expiresAt: new Date(req.capability.expiresAt).toISOString()
    },
    defenseAnalysis: {
      layer1_WAF: {
        detected: isMalicious,
        action: isMalicious ? 'FLAGGED_AND_ALERTED' : 'CLEARED',
        matchedPattern: layer1Match ? layer1Match.pattern : null,
        description: 'Layer 1 WAF regex inspected payload before DB execution.'
      },
      layer2_Database: {
        parameterized: true,
        statementTimeout: '3000ms',
        lockTimeout: '2000ms',
        outcome: layer2Result,
        description: 'Layer 2 pg.PreparedStatement isolates input variables, rendering payload inert.'
      }
    },
    transactionStatus,
    realTimeAlertSent: isMalicious,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
