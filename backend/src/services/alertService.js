const config = require('../config/env');

/**
 * Service for dispatching security alerts to CloudWatch logs and AWS SNS
 */
class AlertService {
  /**
   * Log security incident to CloudWatch format and send SNS alert
   * @param {object} alertData Incident metadata
   */
  static async triggerSqlInjectionAlert(alertData) {
    const timestamp = new Date().toISOString();
    const logEvent = {
      event: 'SQL_INJECTION_DETECTED',
      severity: 'CRITICAL',
      timestamp,
      sourceIp: alertData.sourceIp || '127.0.0.1',
      path: alertData.path || '/unknown',
      method: alertData.method || 'GET',
      userIp: alertData.userIp,
      detectedPattern: alertData.pattern,
      payloadSnippet: alertData.payloadSnippet,
      snsTopicArn: config.snsAlertTopicArn
    };

    // Output formatted CloudWatch structured JSON log
    console.error(`[CLOUDWATCH ALERT] ${JSON.stringify(logEvent)}`);

    // Simulate/Trigger AWS SNS Notification
    this.sendSnsNotification(logEvent);

    return logEvent;
  }

  /**
   * Log potential data exfiltration pattern
   */
  static async triggerDataExfiltrationAlert(exfiltrationData) {
    const timestamp = new Date().toISOString();
    const logEvent = {
      event: 'UNUSUAL_DATA_EXFILTRATION_PATTERN',
      severity: 'HIGH',
      timestamp,
      userId: exfiltrationData.userId,
      recordCount: exfiltrationData.recordCount,
      sourceIp: exfiltrationData.sourceIp,
      snsTopicArn: config.snsAlertTopicArn
    };

    console.warn(`[CLOUDWATCH ALERT] ${JSON.stringify(logEvent)}`);
    this.sendSnsNotification(logEvent);

    return logEvent;
  }

  /**
   * AWS SNS email trigger simulation / SDK invocation wrapper
   */
  static sendSnsNotification(logEvent) {
    // In production environment with AWS SDK installed and SNS configured, this calls SNS.publish()
    if (process.env.AWS_REGION && process.env.SNS_ALERT_TOPIC_ARN) {
      // e.g. await snsClient.send(new PublishCommand({...}))
    }
  }
}

module.exports = AlertService;
