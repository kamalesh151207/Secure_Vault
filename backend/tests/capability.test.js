const { generateCapabilityToken, verifyCapabilityToken } = require('../src/capability/capabilityToken');

describe('HMAC-SHA256 Capability Token Mechanism', () => {
  const userId = 42;
  const customSecret = 'test_hmac_secret_key_32_bytes_len!!';

  test('should generate a valid capability token with signature', () => {
    const res = generateCapabilityToken(userId, 'write:pentest', customSecret);
    expect(res).toHaveProperty('token');
    expect(res).toHaveProperty('expiresAt');
    expect(res.token).toContain('.');

    const verification = verifyCapabilityToken(res.token, customSecret);
    expect(verification.valid).toBe(true);
    expect(verification.payload.userId).toBe('42');
    expect(verification.payload.scope).toBe('write:pentest');
  });

  test('should reject forged capability token with invalid signature', () => {
    const res = generateCapabilityToken(userId, 'write:pentest', customSecret);
    const parts = res.token.split('.');
    
    // Forged signature
    const forgedToken = `${parts[0]}.forged_signature_abc123`;
    const verification = verifyCapabilityToken(forgedToken, customSecret);

    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain('Invalid capability token signature');
  });

  test('should reject expired capability token (> 5 minutes)', () => {
    // Generate token with past timestamp
    const res = generateCapabilityToken(userId, 'write:pentest', customSecret);
    const parts = res.token.split('.');
    
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    payload.expiresAt = Date.now() - 1000; // Expired 1 second ago

    const expiredPayloadString = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    const crypto = require('crypto');
    const hmac = crypto.createHmac('sha256', customSecret);
    hmac.update(expiredPayloadString);
    const signature = hmac.digest('base64url');

    const expiredToken = `${expiredPayloadString}.${signature}`;

    const verification = verifyCapabilityToken(expiredToken, customSecret);
    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain('expired');
  });
});
