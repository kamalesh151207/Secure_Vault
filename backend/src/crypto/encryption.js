const crypto = require('crypto');
const config = require('../config/env');

/**
 * AES-256-GCM Envelope Encryption Utility
 */
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits standard for GCM
const AUTH_TAG_LENGTH = 16;

/**
 * Derive a 32-byte key from master key or raw buffer
 */
function getEncryptionKey(customMasterKey) {
  const masterKey = customMasterKey || config.kmsMasterKey;
  if (Buffer.isBuffer(masterKey) && masterKey.length === 32) {
    return masterKey;
  }
  // Convert hex string or hash to 32 bytes
  if (typeof masterKey === 'string' && masterKey.length === 64) {
    return Buffer.from(masterKey, 'hex');
  }
  return crypto.createHash('sha256').update(String(masterKey)).digest();
}

/**
 * Encrypt sensitive plain text using AES-256-GCM
 * @param {string} text Plaintext input
 * @param {string|Buffer} [customKey] Optional key override
 * @returns {object} { ciphertext, iv, tag, formatted }
 */
function encryptField(text, customKey = null) {
  if (text === undefined || text === null) {
    return null;
  }

  const key = getEncryptionKey(customKey);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  let encrypted = cipher.update(String(text), 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag().toString('hex');
  const ivHex = iv.toString('hex');

  // Format: iv:tag:ciphertext
  const formatted = `${ivHex}:${tag}:${encrypted}`;

  return {
    ciphertext: encrypted,
    iv: ivHex,
    tag: tag,
    formatted: formatted
  };
}

/**
 * Decrypt string encrypted with AES-256-GCM
 * @param {string|object} encryptedInput Formatted string (iv:tag:ciphertext) or object
 * @param {string|Buffer} [customKey] Optional key override
 * @returns {string} Decrypted plaintext
 */
function decryptField(encryptedInput, customKey = null) {
  if (!encryptedInput) return null;

  let ivHex, tagHex, ciphertextHex;

  if (typeof encryptedInput === 'string') {
    const parts = encryptedInput.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format. Expected iv:tag:ciphertext');
    }
    [ivHex, tagHex, ciphertextHex] = parts;
  } else if (typeof encryptedInput === 'object') {
    ivHex = encryptedInput.iv;
    tagHex = encryptedInput.tag;
    ciphertextHex = encryptedInput.ciphertext;
  } else {
    throw new Error('Unsupported encrypted input format');
  }

  const key = getEncryptionKey(customKey);
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  decipher.setAuthTag(tag);

  let decrypted = decipher.update(ciphertextHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Generate cryptographic salt
 */
function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash password with PBKDF2 using SHA-512
 */
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

module.exports = {
  encryptField,
  decryptField,
  generateSalt,
  hashPassword,
  getEncryptionKey
};
