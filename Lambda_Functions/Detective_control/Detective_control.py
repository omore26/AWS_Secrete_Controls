import boto3
import json

config = boto3.client("config")

def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    config_item = invoking_event["configurationItem"]

    resource_type = config_item["resourceType"]
    resource_id = config_item["resourceId"]

    compliance_type = "COMPLIANT"
    annotation = "EC2 instance is not publicly accessible."

    if resource_type != "AWS::EC2::Instance":
        compliance_type = "NOT_APPLICABLE"
        annotation = "This rule only checks EC2 instances."
    else:
        configuration = config_item.get("configuration", {})
        public_ip = configuration.get("publicIpAddress")

        if public_ip:
            compliance_type = "NON_COMPLIANT"
            annotation = f"EC2 instance has public IP address: {public_ip}"

    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": resource_type,
                "ComplianceResourceId": resource_id,
                "ComplianceType": compliance_type,
                "Annotation": annotation,
                "OrderingTimestamp": config_item["configurationItemCaptureTime"],
            }
        ],
        ResultToken=event["resultToken"],
    )