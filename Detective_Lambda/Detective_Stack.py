from aws_cdk import (
    Stack,
    Duration,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_config as config,
)

from constructs import Construct


class SecurityGroupSshCheckStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # Lambda Function
        sg_check_lambda = lambda_.Function(
            self,
            "SgSshOpenChecker",
            function_name="sg-ssh-open-checker",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="Detective_Function.lambda_handler",
            code=lambda_.Code.from_asset("Stack_function"),
            timeout=Duration.seconds(60),
        )

        # Permission for Lambda to send evaluation to AWS Config
        sg_check_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "config:PutEvaluations",
                ],
                resources=["*"],
            )
        )

        # Allow AWS Config to invoke Lambda
        sg_check_lambda.add_permission(
            "AllowConfigInvoke",
            principal=iam.ServicePrincipal("config.amazonaws.com"),
            action="lambda:InvokeFunction",
        )

        # Conformance Pack YAML Template
        conformance_pack_template = f"""
Resources:
  SgSshOpenRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: sg-ssh-open-check
      Description: Detects Security Groups with SSH open to internet
      Scope:
        ComplianceResourceTypes:
          - AWS::EC2::SecurityGroup

      Source:
        Owner: CUSTOM_LAMBDA
        SourceIdentifier: {sg_check_lambda.function_arn}

        SourceDetails:
          - EventSource: aws.config
            MessageType: ConfigurationItemChangeNotification
"""

        # Conformance Pack
        config.CfnConformancePack(
            self,
            "SecurityGroupSSHConformancePack",
            conformance_pack_name="security-group-ssh-conformance-pack",
            template_body=conformance_pack_template,
        )