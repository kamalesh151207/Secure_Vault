const { getDb } = require('../db/database');

/**
 * Service for managing immutable security audit logs
 */
class AuditLogger {
  /**
   * Log query attempt to database logs table
   * @param {object} params Log attributes
   */
  static async logQuery({ userId = null, queryText, isMalicious = false, sourceIp = '127.0.0.1' }) {
    const db = getDb();
    const timestamp = new Date().toISOString();

    try {
      const result = await db.query(
        `INSERT INTO logs (user_id, query_text, is_malicious, timestamp, source_ip)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, timestamp`,
        [userId, queryText, isMalicious ? 1 : 0, timestamp, sourceIp]
      );
      return result.rows[0];
    } catch (err) {
      console.error('[AuditLogger] Failed to write security log entry:', err.message);
      return null;
    }
  }

  /**
   * Retrieve recent security logs for dashboard display
   */
  static async getRecentLogs(limit = 50) {
    const db = getDb();
    try {
      const result = await db.query(
        `SELECT id, user_id, query_text, is_malicious, timestamp, source_ip
         FROM logs
         ORDER BY id DESC
         LIMIT $1`,
        [limit]
      );
      return result.rows;
    } catch (err) {
      console.error('[AuditLogger] Failed to fetch security logs:', err.message);
      return [];
    }
  }
}

module.exports = AuditLogger;
