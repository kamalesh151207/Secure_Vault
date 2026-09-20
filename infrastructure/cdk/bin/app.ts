#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecureVaultStack } from '../lib/secure-vault-stack';

const app = new cdk.App();
new SecureVaultStack(app, 'SecureVaultStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT || '123456789012',
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1',
  },
  description: 'SecureVault Serverless AntiGravity SQL Injection Prevention Stack'
});
