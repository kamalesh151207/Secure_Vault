import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as path from 'path';

export class SecureVaultStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 1. VPC with Public & Isolated Subnets
    const vpc = new ec2.Vpc(this, 'SecureVaultVpc', {
      maxAzs: 2,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'PublicSubnet',
          subnetType: ec2.SubnetType.PUBLIC,
        },
        {
          cidrMask: 24,
          name: 'IsolatedDatabaseSubnet',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        }
      ]
    });

    // Security Group for RDS PostgreSQL
    const dbSecurityGroup = new ec2.SecurityGroup(this, 'DbSecurityGroup', {
      vpc,
      description: 'Allow PostgreSQL access from Lambda function only',
      allowAllOutbound: false
    });

    // 2. Amazon RDS PostgreSQL Instance
    const dbInstance = new rds.DatabaseInstance(this, 'SecureVaultRds', {
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.VER_15
      }),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      securityGroups: [dbSecurityGroup],
      databaseName: 'securevault',
      credentials: rds.Credentials.fromGeneratedSecret('vault_user'),
      allocatedStorage: 20,
      maxAllocatedStorage: 50,
      autoMinorVersionUpgrade: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY // For demo cleanup
    });

    // 3. SNS Topic for Security Alerts
    const alertTopic = new sns.Topic(this, 'SqlInjectionAlertTopic', {
      displayName: 'SecureVault Real-Time SQL Injection & Data Exfiltration Alerts'
    });

    // 4. AWS Lambda Function (Node.js 18.x, 512 MB)
    const backendLambda = new lambda.Function(this, 'BackendLambdaFunction', {
      runtime: lambda.Runtime.NODEJS_18_X,
      memorySize: 512,
      timeout: cdk.Duration.seconds(10),
      handler: 'src/lambda.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../../backend')),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      environment: {
        DB_HOST: dbInstance.dbInstanceEndpointAddress,
        DB_PORT: '5432',
        DB_NAME: 'securevault',
        DB_USER: 'vault_user',
        KMS_MASTER_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        HMAC_SECRET: 'cdk_production_hmac_secret_32_bytes_len!',
        JWT_SECRET: 'cdk_production_jwt_secret_32_bytes_len!',
        SNS_ALERT_TOPIC_ARN: alertTopic.topicArn,
        ENABLE_MOCK_DB: 'false'
      }
    });

    // Allow Lambda to connect to PostgreSQL Security Group
    dbSecurityGroup.addIngressRule(
      backendLambda.connections.securityGroups[0],
      ec2.Port.tcp(5432),
      'Allow PostgreSQL connections from Lambda'
    );

    // Grant Lambda permissions to publish to SNS Topic
    alertTopic.grantPublish(backendLambda);

    // 5. API Gateway with Rate Limiting & Throttle Control
    const api = new apigateway.LambdaRestApi(this, 'SecureVaultApi', {
      handler: backendLambda,
      proxy: true,
      deployOptions: {
        stageName: 'prod',
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS
      }
    });

    // 6. S3 Bucket & CloudFront Distribution for Frontend Assets
    const frontendBucket = new s3.Bucket(this, 'FrontendBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY
    });

    const distribution = new cloudfront.Distribution(this, 'SecureVaultDistribution', {
      defaultBehavior: {
        origin: new origins.S3Origin(frontendBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED
      }
    });

    // Stack Outputs
    new cdk.CfnOutput(this, 'ApiGatewayUrl', {
      value: api.url,
      description: 'SecureVault AntiGravity API Gateway Endpoint'
    });

    new cdk.CfnOutput(this, 'CloudFrontUrl', {
      value: `https://${distribution.distributionDomainName}`,
      description: 'CloudFront CDN Static Frontend Distribution URL'
    });

    new cdk.CfnOutput(this, 'SnsAlertTopicArn', {
      value: alertTopic.topicArn,
      description: 'SNS Security Incident Alert Topic ARN'
    });
  }
}
