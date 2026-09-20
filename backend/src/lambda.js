const serverless = require('serverless-http');
const app = require('./app');

/**
 * AWS Lambda Handler Export
 */
module.exports.handler = serverless(app);
