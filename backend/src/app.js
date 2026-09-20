const express = require('express');
const cors = require('cors');
const { wafSecurityMiddleware } = require('./middleware/wafSecurity');
const authRoutes = require('./routes/auth');
const dataRoutes = require('./routes/data');
const capabilityRoutes = require('./routes/capability');
const testRoutes = require('./routes/test');
const AuditLogger = require('./services/auditLogger');
const { initializeSchema } = require('./db/database');

const app = express();

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Initialize Database Schema on startup
initializeSchema();

// Layer 1 WAF & Regex Security Inspector (Runs on all incoming requests)
app.use(wafSecurityMiddleware);

// Healthcheck
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: 'SecureVault AntiGravity Backend',
    timestamp: new Date().toISOString(),
    security: {
      layer1_WAF: 'Active',
      layer2_PreparedStatements: 'Active',
      encryption: 'AES-256-GCM',
      capabilityTokens: 'HMAC-SHA256 (5min)'
    }
  });
});

// API Routes
app.use('/auth', authRoutes);
app.use('/data', dataRoutes);
app.use('/capability', capabilityRoutes);
app.use('/test', testRoutes);

// Endpoint for security audit logs visualizer
app.get('/logs', async (req, res) => {
  try {
    const logs = await AuditLogger.getRecentLogs(50);
    res.json({
      count: logs.length,
      logs
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch logs', message: err.message });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', message: `Route ${req.method} ${req.path} does not exist.` });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Global Error]', err);
  res.status(500).json({ error: 'Internal Server Error', message: err.message });
});

module.exports = app;
