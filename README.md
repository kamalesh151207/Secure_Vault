# 🛡️ SecureVault - AntiGravity Cloud SQL Injection Prevention & Data Leak Detection System

**SecureVault** is a production-ready, serverless security system designed to prevent SQL injection data leaks, enforce double-layer threat detection, manage AES-256-GCM envelope encryption for stored PII, and provide time-limited write access via HMAC-signed Capability Codes.

---

## 🎯 Key Architectural Features

1. **AntiGravity Cloud Serverless Stack**:
   - **AWS Lambda + API Gateway**: Auto-scales to zero, pay-per-use backend architecture.
   - **Amazon RDS (PostgreSQL)**: Isolated in a private VPC subnet with strict parameterization and connection statement timeouts (`statement_timeout = 3000ms`, `lock_timeout = 2000ms`).
2. **Double-Layer SQL Injection Security**:
   - **Layer 1 (Runtime WAF / Input Validation)**: Regex rules inspecting incoming query parameters and payloads for SQL injection signatures (`' OR 1=1 --`, `UNION SELECT`, `; DROP TABLE`, `EXEC()`, stacked queries).
   - **Layer 2 (Database Parameterization)**: `pg.PreparedStatement` bound variable execution. Absolutely zero string concatenation.
3. **AES-256-GCM Envelope Encryption**:
   - Encrypts user credentials and sensitive PII on-the-fly.
   - Generates a random 12-byte IV and 16-byte authentication tag per record.
   - Formatted and stored as `iv:tag:ciphertext`.
4. **Capability Code Authorization (HMAC-SHA256)**:
   - Time-limited token (5 minutes validity) signing `{userId, timestamp, scope, nonce}`.
   - Included via `X-Capability-Token` header. Grants temporary write access (`INSERT`, `UPDATE`, `DELETE`, pen-test mode); otherwise all queries remain strictly read-only.
5. **Data Leak Detection & Real-Time Alerting**:
   - Instant CloudWatch structured JSON log event.
   - Triggers AWS SNS email alerts upon detecting malicious injection attempts or exfiltration patterns.

---

## 🧱 Repository Structure

```
secure-vault/
├── backend/
│   ├── src/
│   │   ├── config/            # Environment configurations
│   │   ├── crypto/            # AES-256-GCM Envelope Encryption
│   │   ├── capability/        # HMAC-SHA256 Capability Tokens
│   │   ├── db/                # PostgreSQL Pool & In-Memory Driver
│   │   ├── middleware/        # Layer 1 WAF & JWT Auth Middleware
│   │   ├── routes/            # /auth, /data, /capability, /test
│   │   ├── services/          # CloudWatch & SNS Alerting + Audit Logger
│   │   ├── app.js             # Express Application
│   │   ├── lambda.js          # AWS Lambda Handler Wrapper
│   │   └── server.js          # Local Server Bootstrap
│   ├── tests/                 # Jest Unit Tests (Encryption, Capability, SQL Validation)
│   ├── package.json
│   └── .env.example
├── frontend/                  # Interactive Glassmorphic Web App
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── infrastructure/
│   ├── cdk/                   # AWS CDK TypeScript IaC
│   └── terraform/             # Terraform main.tf configuration
├── postman/
│   └── SecureVault.postman_collection.json
└── README.md
```

---

## 🚀 Step 1: Running Locally

### 1. Install Backend Dependencies
```bash
cd backend
npm install
```

### 2. Run Unit Tests
```bash
npm test
```

### 3. Start Local Server
```bash
npm start
```
The server will start at `http://localhost:3001` with double-layer protection and an active safe in-memory parameterized engine.

### 4. Launch Interactive Frontend
Open `frontend/index.html` in your web browser (or serve via any static file server).

---

## 🧪 Demonstration: SQL Injection Attack & Defense

### 1. Requesting a Capability Code
```http
POST /capability/generate
Authorization: Bearer <YOUR_JWT_TOKEN>
```
**Response**:
```json
{
  "message": "Capability Code generated successfully. Valid for 5 minutes (300 seconds).",
  "capabilityCode": "eyJ1c2VySWQiOiIxIiwidGltZXN0YW1wIjoxNzI1MjA0MDAwMDAwLCJleHBpcmVzQXQiOjE3MjUyMDQzMDAwMDAsInNjb3BlIjoid3JpdGU6cGVudGVzdCIsIm5vbmNlIjoiYTFiMmMzZDQifQ.X9aB8c...signature",
  "expiresInSeconds": 300
}
```

### 2. Submitting an SQL Injection Attack Payload (`' OR '1'='1`)
```http
POST /test/inject
Content-Type: application/json
X-Capability-Token: <YOUR_CAPABILITY_TOKEN>

{
  "payload": "' OR '1'='1",
  "simulateParameterization": true
}
```

### 3. System Defense Output (Layer 1 WAF + Layer 2 Parameterization + CloudWatch Alert)
```json
{
  "message": "Pen-test payload analyzed inside sandboxed transaction.",
  "capabilityAuthorized": true,
  "defenseAnalysis": {
    "layer1_WAF": {
      "detected": true,
      "action": "FLAGGED_AND_ALERTED",
      "matchedPattern": "/((\\%3D)|(=))[^\\n]*((%27)|(')|(%3D)|(=)|(%23)|(#))/i",
      "description": "Layer 1 WAF regex inspected payload before DB execution."
    },
    "layer2_Database": {
      "parameterized": true,
      "statementTimeout": "3000ms",
      "outcome": {
        "success": true,
        "mode": "Parameterized Prepared Statement (Layer 2 Defense)",
        "recordsReturned": 0,
        "explanation": "Parameterized query treated the payload strictly as literal data. Zero SQL injection risk."
      }
    }
  },
  "transactionStatus": "EXECUTED_AND_ROLLED_BACK",
  "realTimeAlertSent": true
}
```

---

## ☁️ Deployment Instructions

### Option A: AWS CDK
```bash
cd infrastructure/cdk
npm install
npm run build
npx cdk deploy
```

### Option B: Terraform
```bash
cd infrastructure/terraform
terraform init
terraform apply
```

---

## 📬 Postman Collection

Import `postman/SecureVault.postman_collection.json` into Postman to test all endpoints. Set environment variable `baseUrl` to `http://localhost:3001` or your API Gateway endpoint URL.
