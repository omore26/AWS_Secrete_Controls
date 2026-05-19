import boto3
import json

ec2 = boto3.client("ec2")

def lambda_handler(event, context):
    if isinstance(event, str):
        event = json.loads(event)

    instance_id = event.get("InstanceId") or event.get("ResourceId") or event.get("RESOURCE_ID")

    if not instance_id:
        return {"status": "FAILED", "message": "Instance ID was not provided."}

    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]

        public_ip = instance.get("PublicIpAddress")

        if not public_ip:
            return {"status": "SUCCESS", "message": "Instance does not have a public IP."}

        addresses = ec2.describe_addresses(
            Filters=[
                {
                    "Name": "public-ip",
                    "Values": [public_ip]
                }
            ]
        )

        for address in addresses.get("Addresses", []):
            association_id = address.get("AssociationId")

            if association_id:
                ec2.disassociate_address(AssociationId=association_id)

        ec2.stop_instances(InstanceIds=[instance_id])

        return {
            "status": "SUCCESS",
            "message": f"Public access removed and instance stopped: {instance_id}"
        }

    except Exception as error:
        return {"status": "FAILED", "message": str(error)}
