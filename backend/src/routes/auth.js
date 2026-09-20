const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const { getDb } = require('../db/database');
const { encryptField, generateSalt, hashPassword } = require('../crypto/encryption');
const AuditLogger = require('../services/auditLogger');

/**
 * POST /auth/register
 * Creates a new user account with AES-256-GCM encrypted email and hashed password
 */
router.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({
      error: 'Validation Error',
      message: 'Username, password, and email are required fields.'
    });
  }

  const db = getDb();
  const sourceIp = req.ip || '127.0.0.1';

  try {
    // Check if username exists (using parameterized query)
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows && existingUser.rows.length > 0) {
      return res.status(409).json({
        error: 'User Exists',
        message: `Username '${username}' is already registered.`
      });
    }

    // Generate cryptographic salt and hash password
    const salt = generateSalt();
    const hashedPassword = hashPassword(password, salt);

    // Encrypt password representation & sensitive email with AES-256-GCM envelope encryption
    const encryptedEmail = encryptField(email);
    const encryptedPassword = encryptField(hashedPassword);

    const createdAt = new Date().toISOString();

    // Store user with parameterization
    const result = await db.query(
      `INSERT INTO users (username, encrypted_password, encrypted_email, salt, created_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, created_at`,
      [username, encryptedPassword.formatted, encryptedEmail.formatted, salt, createdAt]
    );

    const newUser = result.rows[0];

    // Audit log
    await AuditLogger.logQuery({
      userId: newUser.id,
      queryText: `REGISTER USER username=${username}`,
      isMalicious: false,
      sourceIp
    });

    // Generate JWT
    const token = jwt.sign(
      { id: newUser.id, username: newUser.username },
      config.jwtSecret,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully with AES-256-GCM encryption.',
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        emailEncryptedFormat: encryptedEmail.formatted,
        encryptionAlgorithm: 'AES-256-GCM',
        createdAt: newUser.created_at
      }
    });
  } catch (err) {
    console.error('[Auth Register Error]', err);
    res.status(500).json({
      error: 'Registration Failed',
      message: err.message
    });
  }
});

/**
 * POST /auth/login
 * Authenticates user credentials using parameterized queries
 */
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: 'Validation Error',
      message: 'Username and password are required.'
    });
  }

  const db = getDb();
  const sourceIp = req.ip || '127.0.0.1';

  try {
    // Parameterized SQL query - absolutely no string concatenation!
    const queryResult = await db.query(
      'SELECT id, username, encrypted_password, encrypted_email, salt, created_at FROM users WHERE username = $1',
      [username]
    );

    if (!queryResult.rows || queryResult.rows.length === 0) {
      await AuditLogger.logQuery({
        userId: null,
        queryText: `FAILED LOGIN ATTEMPT username=${username}`,
        isMalicious: false,
        sourceIp
      });
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid username or password.'
      });
    }

    const user = queryResult.rows[0];
    const hashedPasswordInput = hashPassword(password, user.salt);

    // Verify password against stored encrypted password
    let storedHashedPassword;
    try {
      storedHashedPassword = require('../crypto/encryption').decryptField(user.encrypted_password);
    } catch (e) {
      storedHashedPassword = user.encrypted_password;
    }

    if (storedHashedPassword !== hashedPasswordInput) {
      await AuditLogger.logQuery({
        userId: user.id,
        queryText: `INVALID PASSWORD LOGIN username=${username}`,
        isMalicious: false,
        sourceIp
      });
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid username or password.'
      });
    }

    // Success audit log
    await AuditLogger.logQuery({
      userId: user.id,
      queryText: `SUCCESSFUL LOGIN username=${username}`,
      isMalicious: false,
      sourceIp
    });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      config.jwtSecret,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Authentication successful.',
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (err) {
    console.error('[Auth Login Error]', err);
    res.status(500).json({
      error: 'Login Failed',
      message: err.message
    });
  }
});

module.exports = router;
