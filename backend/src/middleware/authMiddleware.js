const jwt = require('jsonwebtoken');
const config = require('../config/env');

/**
 * JWT Authentication Middleware
 */
function authenticateJwt(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Authentication Required',
      code: 'MISSING_JWT_TOKEN',
      message: 'Bearer Authorization token required.'
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      error: 'Invalid Token',
      code: 'INVALID_JWT_TOKEN',
      message: err.message
    });
  }
}

module.exports = {
  authenticateJwt
};
