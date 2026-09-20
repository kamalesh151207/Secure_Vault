const { encryptField, decryptField, generateSalt, hashPassword } = require('../src/crypto/encryption');

describe('AES-256-GCM Envelope Encryption', () => {
  const samplePlaintext = 'user_pii_secret_social_security_number_1234';

  test('should encrypt plaintext into iv:tag:ciphertext formatted string', () => {
    const encrypted = encryptField(samplePlaintext);
    expect(encrypted).toHaveProperty('ciphertext');
    expect(encrypted).toHaveProperty('iv');
    expect(encrypted).toHaveProperty('tag');
    expect(encrypted).toHaveProperty('formatted');

    // IV should be 12 bytes = 24 hex characters
    expect(encrypted.iv.length).toBe(24);
    // Auth tag should be 16 bytes = 32 hex characters
    expect(encrypted.tag.length).toBe(32);
    // Formatted string split test
    const parts = encrypted.formatted.split(':');
    expect(parts.length).toBe(3);
  });

  test('should generate unique IV for every encryption call (randomized per record)', () => {
    const enc1 = encryptField(samplePlaintext);
    const enc2 = encryptField(samplePlaintext);

    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
  });

  test('should correctly decrypt encrypted string back to original plaintext', () => {
    const encrypted = encryptField(samplePlaintext);
    const decrypted = decryptField(encrypted.formatted);
    expect(decrypted).toBe(samplePlaintext);
  });

  test('should fail authentication tag check if ciphertext is tampered with', () => {
    const encrypted = encryptField(samplePlaintext);
    const parts = encrypted.formatted.split(':');
    
    // Tamper with the ciphertext by flipping last character
    const tamperedCiphertext = parts[2].substring(0, parts[2].length - 1) + (parts[2].endsWith('a') ? 'b' : 'a');
    const tamperedFormatted = `${parts[0]}:${parts[1]}:${tamperedCiphertext}`;

    expect(() => {
      decryptField(tamperedFormatted);
    }).toThrow();
  });

  test('should correctly generate salt and hash password with PBKDF2', () => {
    const password = 'SecretPassword123!';
    const salt = generateSalt(16);
    expect(salt.length).toBe(32); // 16 bytes = 32 hex chars

    const hash1 = hashPassword(password, salt);
    const hash2 = hashPassword(password, salt);
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(128); // 64 bytes = 128 hex chars
  });
});
