import boto3
import enum
import json
import jmespath
import os


class EnvVars(enum.Enum):
    HOSTED_ZONE_ID = enum.auto()

    @property
    def value(self):
        return os.environ[self.name]


def handler(event, context=None):
    print(json.dumps(event))
    certificate_arn = event["detail"]["requestParameters"]["certificateArn"]
    acm = boto3.client('acm')
    response = acm.describe_certificate(CertificateArn=certificate_arn)
    records = jmespath.search('Certificate.DomainValidationOptions[].ResourceRecord', response)
    route53 = boto3.client('route53')
    response = route53.change_resource_record_sets(
        HostedZoneId=EnvVars.HOSTED_ZONE_ID.value,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record["Name"],
                        "Type": record["Type"],
                        "TTL": 300,
                        "ResourceRecords": [{
                            "Value": record["Value"],
                        }],
                    },
                }
                for record in records
            ],
        }
    )
