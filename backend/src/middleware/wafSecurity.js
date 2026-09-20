const AlertService = require('../services/alertService');
const AuditLogger = require('../services/auditLogger');

// Layer 1 SQL Injection Detection Regular Expressions
const SQLI_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i, // Quotes, comments
  /((\%3D)|(=))[^\n]*((%27)|(')|(%3D)|(=)|(%23)|(#))/i, // Basic boolean matching e.g. ' OR '1'='1
  /\w*((\%27)|(\'))(\s*)((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i, // ' OR
  /((\%27)|(\'))\s*(union|select|insert|update|delete|drop|alter|create|truncate|exec|execute|concat|sleep|pg_sleep|benchmark)/i, // Union/SQL verbs
  /union\s+all\s+select/i, // UNION ALL SELECT
  /union\s+select/i, // UNION SELECT
  /;\s*(drop|delete|update|insert|alter|create)/i, // Stacked query commands
  /exec(\s|\+)+(s|x)p\w+/i, // Stored procedure execution
  /0x[0-9a-f]+/i // Hexadecimal literal injections
];

/**
 * Scan string input for SQL injection signatures
 * @param {string} value Value to inspect
 * @returns {object|null} Matched pattern details or null
 */
function scanValueForSqli(value) {
  if (!value || typeof value !== 'string') return null;

  for (const pattern of SQLI_PATTERNS) {
    if (pattern.test(value)) {
      return {
        matchedText: value,
        pattern: pattern.toString()
      };
    }
  }
  return null;
}

/**
 * Deep recursive inspection of objects/arrays
 */
function inspectPayload(obj) {
  if (!obj) return null;

  if (typeof obj === 'string') {
    return scanValueForSqli(obj);
  }

  if (typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      const match = inspectPayload(obj[key]);
      if (match) return match;
    }
  }

  return null;
}

/**
 * Layer 1 WAF Middleware - Inspects all incoming HTTP requests
 */
async function wafSecurityMiddleware(req, res, next) {
  const sourceIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  
  // Inspect query params, body, and request params
  const sqliMatch = inspectPayload(req.query) || inspectPayload(req.body) || inspectPayload(req.params);

  if (sqliMatch) {
    req.isMaliciousPayload = true;
    req.sqliDetails = sqliMatch;

    // Trigger CloudWatch & SNS Real-Time Alert
    await AlertService.triggerSqlInjectionAlert({
      sourceIp,
      path: req.path,
      method: req.method,
      pattern: sqliMatch.pattern,
      payloadSnippet: String(sqliMatch.matchedText).substring(0, 100)
    });

    // Write to audit log table
    await AuditLogger.logQuery({
      userId: req.user ? req.user.id : null,
      queryText: `${req.method} ${req.path} - Payload: ${JSON.stringify(req.body || req.query)}`,
      isMalicious: true,
      sourceIp
    });

    // If request is hitting the pen-test sandbox endpoint, allow request to proceed to route handler
    // so it can demonstrate transaction rollback mechanics safely.
    if (req.path.includes('/test/inject')) {
      return next();
    }

    // Otherwise, Layer 1 WAF immediately blocks malicious payload
    return res.status(400).json({
      error: 'WAF Security Block',
      code: 'SQL_INJECTION_DETECTED',
      layer: 'Layer 1 (WAF Input Validation)',
      message: 'Suspicious SQL injection payload pattern detected and blocked by Layer 1 security rules.',
      detectedPattern: sqliMatch.pattern,
      timestamp: new Date().toISOString()
    });
  }

  next();
}

module.exports = {
  wafSecurityMiddleware,
  scanValueForSqli,
  SQLI_PATTERNS
};
