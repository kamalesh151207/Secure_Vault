const dotenv = require('dotenv');
dotenv.config();

module.exports = {
  port: process.env.PORT || 3001,
  nodeEnv: process.env.NODE_ENV || 'development',
  db: {
    host: process.env.DB_HOST || 'aws-0-ap-northeast-1.pooler.supabase.com',
    port: parseInt(process.env.DB_PORT || '6543', 10),
    name: process.env.DB_NAME || 'postgres',
    user: process.env.DB_USER || 'postgres.ytlutuzkqhbhtjwnnpvf',
    password: process.env.DB_PASS || 'secure_vault@',
    url: process.env.DATABASE_URL || 'postgresql://postgres.ytlutuzkqhbhtjwnnpvf:secure_vault%40@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres'
  },
  kmsMasterKey: process.env.KMS_MASTER_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  hmacSecret: process.env.HMAC_SECRET || 'securevault_hmac_secret_key_32_bytes_len!',
  jwtSecret: process.env.JWT_SECRET || 'securevault_jwt_secret_key_32_bytes_len!',
  snsAlertTopicArn: process.env.SNS_ALERT_TOPIC_ARN || 'arn:aws:sns:us-east-1:123456789012:secure-vault-alerts',
  enableMockDb: process.env.ENABLE_MOCK_DB === 'true'
};
