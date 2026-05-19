# EC2 Public IP Detective and Reactive Control

## Overview

This project creates automated AWS Security Control to detect EC2 Instances that have public IP address and remidiate them

Services Used:
-AWS CloudFormation
-AWS Lambda
-AWS Config
-AWS System Manager Automation
-IAM Roles

## Architecture Flow

1.EC2 Configuration
2.AWS Config Rule
3.Detective Lambda
4.Mark EC2 as NON-COMPLIANT
5.AWS Config Remidiation
6.SSM Automation Documentation
7.Reactive Lambda
8.Disassociate Elastic IP if present
9.Stop EC2 Instance