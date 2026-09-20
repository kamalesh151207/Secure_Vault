const crypto = require('crypto');
const config = require('../config/env');

const TOKEN_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes in milliseconds

/**
 * Generate a time-limited HMAC-signed Capability Token
 * @param {string|number} userId User ID
 * @param {string} [scope='write:pentest'] Token scope
 * @param {string} [customSecret] Optional secret override
 * @returns {object} { token, expiresAt, payload }
 */
function generateCapabilityToken(userId, scope = 'write:pentest', customSecret = null) {
  const secret = customSecret || config.hmacSecret;
  const timestamp = Date.now();
  const expiresAt = timestamp + TOKEN_EXPIRY_MS;
  const nonce = crypto.randomBytes(8).toString('hex');

  const payload = {
    userId: String(userId),
    timestamp,
    expiresAt,
    scope,
    nonce
  };

  const payloadString = Buffer.from(JSON.stringify(payload)).toString('base64url');
  
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payloadString);
  const signature = hmac.digest('base64url');

  const token = `${payloadString}.${signature}`;

  return {
    token,
    expiresAt: new Date(expiresAt).toISOString(),
    expiresInSeconds: 300,
    payload
  };
}

/**
 * Verify Capability Token
 * @param {string} token Capability Token string
 * @param {string} [customSecret] Optional secret override
 * @returns {object} { valid: boolean, payload?: object, reason?: string }
 */
function verifyCapabilityToken(token, customSecret = null) {
  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'Capability token missing or invalid type' };
  }

  const parts = token.trim().split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'Malformed capability token structure' };
  }

  const [payloadString, signature] = parts;
  const secret = customSecret || config.hmacSecret;

  // Re-compute HMAC
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payloadString);
  const expectedSignature = hmac.digest('base64url');

  // Constant-time signature comparison to prevent timing attacks
  const sigBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    return { valid: false, reason: 'Invalid capability token signature (HMAC mismatch)' };
  }

  try {
    const payloadJson = Buffer.from(payloadString, 'base64url').toString('utf8');
    const payload = JSON.parse(payloadJson);

    // Check expiration
    if (Date.now() > payload.expiresAt) {
      return { valid: false, reason: 'Capability token has expired (valid for 5 minutes only)' };
    }

    return {
      valid: true,
      payload
    };
  } catch (err) {
    return { valid: false, reason: 'Failed to parse capability token payload' };
  }
}

/**
 * Middleware enforcing Capability Token requirement for write operations
 */
function requireCapabilityTokenMiddleware(req, res, next) {
  // Allow safe GET/HEAD methods unless explicitly testing
  const isWriteMethod = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method);
  
  // Check if header is present
  const tokenHeader = req.headers['x-capability-token'] || 
                     (req.headers['authorization'] && req.headers['authorization'].startsWith('Capability ') 
                      ? req.headers['authorization'].replace('Capability ', '') 
                      : null);

  if (!isWriteMethod && !req.path.includes('/test/inject')) {
    return next();
  }

  if (!tokenHeader) {
    return res.status(403).json({
      error: 'Capability Code Required',
      code: 'CAPABILITY_CODE_MISSING',
      message: 'Write operations and pen-testing endpoints require a valid time-limited capability token (X-Capability-Token header).',
      help: 'Generate a capability code via POST /capability/generate first.'
    });
  }

  const verification = verifyCapabilityToken(tokenHeader);
  if (!verification.valid) {
    return res.status(403).json({
      error: 'Capability Code Authorization Failed',
      code: 'CAPABILITY_CODE_INVALID',
      message: verification.reason
    });
  }

  req.capability = verification.payload;
  next();
}

module.exports = {
  generateCapabilityToken,
  verifyCapabilityToken,
  requireCapabilityTokenMiddleware,
  TOKEN_EXPIRY_MS
};
