import json
import boto3

config_client = boto3.client("config")


def lambda_handler(event, context):

    invoking_event = json.loads(event["invokingEvent"])

    configuration_item = invoking_event["configurationItem"]
    resource_type = configuration_item["resourceType"]
    resource_id = configuration_item["resourceId"]
    capture_time = configuration_item["configurationItemCaptureTime"]

    compliance_type = "COMPLIANT"
    annotation = "Security Group does not allow SSH from internet."

    # Check only Security Groups
    if resource_type != "AWS::EC2::SecurityGroup":

        compliance_type = "NOT_APPLICABLE"
        annotation = "Rule only applies to Security Groups."

    else:

        configuration = configuration_item.get("configuration") or {}

        permissions = configuration.get(
            "ipPermissions",
            []
        )
        for permission in permissions:

            protocol = permission.get("ipProtocol")
            from_port = permission.get("fromPort")
            to_port = permission.get("toPort")

            ssh_allowed = False

            if protocol == "-1":
                ssh_allowed = True

            elif (
                protocol == "tcp"
                and from_port is not None
                and to_port is not None
            ):

                if from_port <= 22 <= to_port:
                    ssh_allowed = True

            # Check IPv4 internet access
            if ssh_allowed:

                for ip_range in permission.get("ipv4Ranges", []):

                    if ip_range.get("cidrIp") == "0.0.0.0/0":

                        compliance_type = "NON_COMPLIANT"

                        annotation = (
                            "Security Group allows SSH from 0.0.0.0/0"
                        )

                        break

                # Check IPv6 internet access
                for ipv6_range in permission.get("ipv6Ranges", []):
                    if ipv6_range.get("cidrIpv6") == "::/0":
                        compliance_type = "NON_COMPLIANT"
                        annotation = (
                            "Security Group allows SSH from ::/0"
                        )
                        break

            if compliance_type == "NON_COMPLIANT":
                break

    # Send result to AWS Config
    config_client.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": resource_type,
                "ComplianceResourceId": resource_id,
                "ComplianceType": compliance_type,
                "Annotation": annotation,
                "OrderingTimestamp": capture_time,
            }
        ],
        ResultToken=event["resultToken"],
    )

    return {
        "resource_id": resource_id,
        "compliance_type": compliance_type,
    }