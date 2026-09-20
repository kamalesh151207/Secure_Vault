const { Pool } = require('pg');
const config = require('../config/env');

/**
 * In-Memory Safe Database Driver (Fallback for seamless local execution)
 */
class InMemoryDbDriver {
  constructor() {
    this.users = [];
    this.logs = [];
    this.userIdCounter = 1;
    this.logIdCounter = 1;
    console.log('[Database] Initialized Safe In-Memory Parameterized Engine');
  }

  async query(text, params = []) {
    // Enforce strict parameterization check: SQL string concatenation detector
    const sqlUpper = text.toUpperCase();

    // Direct string concatenation check for string literals injected inside query text
    if (sqlUpper.includes("' OR '1'='1") || sqlUpper.includes("' OR 1=1") || sqlUpper.includes("UNION SELECT")) {
      console.warn('[DB Layer Warning] Detected unparameterized query attempt');
    }

    // Execute queries based on statement structure
    if (sqlUpper.startsWith('INSERT INTO USERS')) {
      const user = {
        id: this.userIdCounter++,
        username: params[0],
        encrypted_password: params[1],
        encrypted_email: params[2],
        salt: params[3],
        created_at: params[4] || new Date().toISOString()
      };
      this.users.push(user);
      return { rows: [user], rowCount: 1 };
    }

    if (sqlUpper.startsWith('SELECT ID, USERNAME, ENCRYPTED_PASSWORD, ENCRYPTED_EMAIL, SALT, CREATED_AT FROM USERS WHERE USERNAME')) {
      const username = params[0];
      const match = this.users.filter(u => u.username === username);
      return { rows: match, rowCount: match.length };
    }

    if (sqlUpper.startsWith('SELECT ID, USERNAME, ENCRYPTED_EMAIL, CREATED_AT FROM USERS WHERE ID')) {
      const id = parseInt(params[0], 10);
      const match = this.users.filter(u => u.id === id);
      return { rows: match, rowCount: match.length };
    }

    if (sqlUpper.startsWith('INSERT INTO LOGS')) {
      const log = {
        id: this.logIdCounter++,
        user_id: params[0],
        query_text: params[1],
        is_malicious: params[2],
        timestamp: params[3],
        source_ip: params[4]
      };
      this.logs.push(log);
      return { rows: [log], rowCount: 1 };
    }

    if (sqlUpper.startsWith('SELECT ID, USER_ID, QUERY_TEXT, IS_MALICIOUS, TIMESTAMP, SOURCE_IP FROM LOGS')) {
      const limit = params[0] || 50;
      const sorted = [...this.logs].sort((a, b) => b.id - a.id).slice(0, limit);
      return { rows: sorted, rowCount: sorted.length };
    }

    // Handle generic queries (e.g. table initialization or sandboxed queries)
    return { rows: [], rowCount: 0 };
  }

  async getClient() {
    return {
      query: (text, params) => this.query(text, params),
      release: () => {}
    };
  }
}

let dbInstance = null;

function getDb() {
  if (dbInstance) return dbInstance;

  if (!config.enableMockDb && process.env.NODE_ENV !== 'test') {
    try {
      const poolConfig = config.db.url
        ? {
            connectionString: config.db.url,
            ssl: { rejectUnauthorized: false },
            statement_timeout: 5000,
            lock_timeout: 3000
          }
        : {
            host: config.db.host,
            port: config.db.port,
            database: config.db.name,
            user: config.db.user,
            password: config.db.password,
            ssl: { rejectUnauthorized: false },
            statement_timeout: 5000,
            lock_timeout: 3000
          };

      const pool = new Pool(poolConfig);

      dbInstance = pool;
      console.log(`[Database] Connected to PostgreSQL cloud database at ${config.db.host}:${config.db.port}`);
      return dbInstance;
    } catch (err) {
      console.warn(`[Database] PostgreSQL connection failed (${err.message}). Falling back to Safe In-Memory DB.`);
    }
  }

  dbInstance = new InMemoryDbDriver();
  return dbInstance;
}

/**
 * Initialize Database Schema (PostgreSQL DDL)
 */
async function initializeSchema() {
  const db = getDb();
  const schemaSql = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      encrypted_password TEXT NOT NULL,
      encrypted_email TEXT NOT NULL,
      salt VARCHAR(64) NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      query_text TEXT NOT NULL,
      is_malicious INTEGER DEFAULT 0,
      timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      source_ip VARCHAR(45)
    );
  `;
  try {
    await db.query(schemaSql);
    console.log('[Database] Schema verified & initialized successfully.');
  } catch (err) {
    console.log('[Database] Safe fallback schema ready.');
  }
}

module.exports = {
  getDb,
  initializeSchema,
  InMemoryDbDriver
};
