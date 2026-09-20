const request = require('supertest');
const app = require('../src/app');
const { scanValueForSqli } = require('../src/middleware/wafSecurity');
const { generateCapabilityToken } = require('../src/capability/capabilityToken');

describe('Double-Layer SQL Injection Security & WAF Rules', () => {
  describe('Layer 1 Regex WAF Inspector', () => {
    const maliciousPayloads = [
      "' OR '1'='1",
      "admin' OR 1=1 --",
      "'; DROP TABLE users; --",
      "UNION SELECT username, encrypted_password FROM users--",
      "1; EXEC xp_cmdshell('dir')",
      "admin' AND SLEEP(5)--"
    ];

    test.each(maliciousPayloads)('should detect SQL injection pattern in payload: %s', (payload) => {
      const match = scanValueForSqli(payload);
      expect(match).not.toBeNull();
      expect(match).toHaveProperty('pattern');
    });

    test('should pass benign inputs without triggering WAF regex', () => {
      const safeInputs = [
        "john_doe",
        "user@example.com",
        "Hello World! This is a standard user comment."
      ];
      safeInputs.forEach(input => {
        const match = scanValueForSqli(input);
        expect(match).toBeNull();
      });
    });
  });

  describe('API Endpoints Security & Sandbox Tests', () => {
    test('POST /test/inject should block request if Capability Token header is missing', async () => {
      const res = await request(app)
        .post('/test/inject')
        .send({ payload: "' OR '1'='1" });

      expect(res.statusCode).toBe(403);
      expect(res.body.code).toBe('CAPABILITY_CODE_MISSING');
    });

    test('POST /test/inject should allow sandboxed transaction evaluation when valid Capability Token is provided', async () => {
      const cap = generateCapabilityToken(1, 'write:pentest');

      const res = await request(app)
        .post('/test/inject')
        .set('X-Capability-Token', cap.token)
        .send({ payload: "' OR '1'='1" });

      expect(res.statusCode).toBe(200);
      expect(res.body.capabilityAuthorized).toBe(true);
      expect(res.body.defenseAnalysis.layer1_WAF.detected).toBe(true);
      expect(res.body.transactionStatus).toBe('EXECUTED_AND_ROLLED_BACK');
    });
  });
});
