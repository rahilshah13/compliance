#!/usr/bin/env node
const cdk = require('aws-cdk-lib');
const { CdkStack } = require('./stack');

const app = new cdk.App();
new CdkStack(app, 'DockerIpv6Stack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'us-west-1',
  },
});