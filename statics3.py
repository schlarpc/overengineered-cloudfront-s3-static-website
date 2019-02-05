from troposphere import (
    AccountId,
    GetAtt,
    Join,
    Output,
    Ref,
    Template,
    AWS_PARTITION,
    Region,
    AccountId,
    NoValue,
    Parameter,
    Equals,
    Not,
    If,
    Select,
    Tags,
)
from troposphere.s3 import (
    AbortIncompleteMultipartUpload,
    Bucket,
    BucketEncryption,
    BucketPolicy,
    LambdaConfigurations,
    LifecycleConfiguration,
    LifecycleRule,
    LifecycleRuleTransition,
    LoggingConfiguration,
    MetricsConfiguration,
    NotificationConfiguration,
    PublicAccessBlockConfiguration,
    ServerSideEncryptionByDefault,
    ServerSideEncryptionRule,
)
from troposphere.cloudfront import (
    CloudFrontOriginAccessIdentity,
    CloudFrontOriginAccessIdentityConfig,
    DefaultCacheBehavior,
    Distribution,
    DistributionConfig,
    ForwardedValues,
    LambdaFunctionAssociation,
    Logging,
    Origin,
    S3OriginConfig,
    ViewerCertificate,
)
from troposphere.sqs import Queue
from troposphere.logs import LogGroup
from troposphere.awslambda import (
    Code,
    DeadLetterConfig,
    Function,
    Permission,
    Version,
    Environment,
)
from troposphere.iam import PolicyProperty, PolicyType, Role
from troposphere.events import Rule, Target
from troposphere.certificatemanager import Certificate

from awacs import logs, s3, sqs, sts
from awacs.aws import Allow, PolicyDocument, Principal, Statement

import argparse
import datetime
import hashlib
import inspect
import json
import textwrap

import certificate_validator
import log_ingest
import packmodule

Partition = Ref(AWS_PARTITION)


def add_condition(template, name, condition):
    template.add_condition(name, condition)
    return name


def create_template():
    template = Template(Description="Static website hosted with S3 and CloudFront")

    acm_certificate_arn = template.add_parameter(
        Parameter(
            "AcmCertificateArn",
            Description="Existing ACM certificate ARN to use for serving TLS",
            Type="String",
            AllowedPattern="(arn:[^:]+:acm:[^:]+:[^:]+:certificate/.+|)",
            Default="",
        )
    )

    hosted_zone_id = template.add_parameter(
        Parameter(
            "HostedZoneId",
            Description="Existing Route 53 zone to use for verifying TLS certificate",
            Type="String",
            AllowedPattern="(Z[A-Z0-9]+|)",
            Default="",
        )
    )

    dns_names = template.add_parameter(
        Parameter(
            "DomainNames",
            Description="Comma-separated list of additional domain names to serve",
            Type="CommaDelimitedList",
            Default="",
        )
    )

    tls_protocol_version = template.add_parameter(
        Parameter(
            "TlsProtocolVersion",
            Description="CloudFront TLS security policy, see https://amzn.to/2DR91Xq for details",
            Type="String",
            Default="TLSv1.1_2016",
        )
    )

    log_retention_days = template.add_parameter(
        Parameter(
            "LogRetentionDays",
            Description="Days to keep CloudFront, S3, and Lambda logs",
            Type="Number",
            AllowedValues=[
                1,
                3,
                5,
                7,
                14,
                30,
                60,
                90,
                120,
                150,
                180,
                365,
                400,
                545,
                731,
                1827,
                3653,
            ],
            Default=365,
        )
    )

    default_ttl_seconds = template.add_parameter(
        Parameter(
            "DefaultTtlSeconds",
            Description="Cache TTL when not set by S3 object headers",
            Type="Number",
            Default=int(datetime.timedelta(minutes=5).total_seconds()),
        )
    )

    using_acm_certificate = add_condition(
        template, "UsingAcmCertificate", Not(Equals(Ref(acm_certificate_arn), ""))
    )

    using_hosted_zone = add_condition(
        template, "UsingHostedZone", Not(Equals(Ref(hosted_zone_id), ""))
    )

    using_dns_names = add_condition(
        template, "UsingDnsNames", Not(Equals(Select(0, Ref(dns_names)), ""))
    )

    log_ingester_dlq = template.add_resource(
        Queue(
            "LogIngesterDLQ",
            MessageRetentionPeriod=int(datetime.timedelta(days=14).total_seconds()),
            KmsMasterKeyId="alias/aws/sqs",
        )
    )

    log_ingester_role = template.add_resource(
        Role(
            "LogIngesterRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect="Allow",
                        Principal=Principal("Service", "lambda.amazonaws.com"),
                        Action=[sts.AssumeRole],
                    )
                ],
            ),
            Policies=[
                PolicyProperty(
                    PolicyName="DLQPolicy",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[sqs.SendMessage],
                                Resource=[GetAtt(log_ingester_dlq, "Arn")],
                            )
                        ],
                    ),
                )
            ],
        )
    )

    log_ingester = template.add_resource(
        Function(
            "LogIngester",
            Runtime="python3.6",
            Handler="index.{}".format(log_ingest.handler.__name__),
            Code=Code(ZipFile=packmodule.pack(inspect.getsource(log_ingest))),
            MemorySize=256,
            Timeout=300,
            Role=GetAtt(log_ingester_role, "Arn"),
            DeadLetterConfig=DeadLetterConfig(
                TargetArn=GetAtt(log_ingester_dlq, "Arn")
            ),
        )
    )

    log_ingester_permission = template.add_resource(
        Permission(
            "LogIngesterPermission",
            FunctionName=GetAtt(log_ingester, "Arn"),
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceAccount=AccountId,
        )
    )

    log_bucket = template.add_resource(
        Bucket(
            "LogBucket",
            AccessControl="LogDeliveryWrite",
            LifecycleConfiguration=LifecycleConfiguration(
                Rules=[
                    LifecycleRule(ExpirationInDays=1, Status="Enabled"),
                    LifecycleRule(
                        AbortIncompleteMultipartUpload=AbortIncompleteMultipartUpload(
                            DaysAfterInitiation=1
                        ),
                        Status="Enabled",
                    ),
                ]
            ),
            NotificationConfiguration=NotificationConfiguration(
                LambdaConfigurations=[
                    LambdaConfigurations(
                        Event="s3:ObjectCreated:*", Function=GetAtt(log_ingester, "Arn")
                    )
                ]
            ),
            BucketEncryption=BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=ServerSideEncryptionByDefault(
                            # if we use KMS, we can't read the logs
                            SSEAlgorithm="AES256"
                        )
                    )
                ]
            ),
            MetricsConfigurations=[MetricsConfiguration(Id="default")],
            DependsOn=[log_ingester_permission],
            PublicAccessBlockConfiguration=PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
        )
    )

    log_ingester_log_group = template.add_resource(
        LogGroup(
            "LogIngesterLogGroup",
            LogGroupName=Join("", ["/aws/lambda/", Ref(log_ingester)]),
            RetentionInDays=Ref(log_retention_days),
        )
    )

    log_ingester_policy = template.add_resource(
        PolicyType(
            "LogIngesterPolicy",
            Roles=[Ref(log_ingester_role)],
            PolicyName="IngestLogPolicy",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                        Resource=[
                            Join(
                                ":",
                                [
                                    "arn",
                                    Partition,
                                    "logs",
                                    Region,
                                    AccountId,
                                    "log-group",
                                    "/aws/cloudfront/*",
                                ],
                            ),
                            Join(
                                ":",
                                [
                                    "arn",
                                    Partition,
                                    "logs",
                                    Region,
                                    AccountId,
                                    "log-group",
                                    "/aws/s3/*",
                                ],
                            ),
                            GetAtt(log_ingester_log_group, "Arn"),
                        ],
                    ),
                    Statement(
                        Effect=Allow,
                        Action=[s3.GetObject],
                        Resource=[Join("", [GetAtt(log_bucket, "Arn"), "/*"])],
                    ),
                ],
            ),
        )
    )

    bucket = template.add_resource(
        Bucket(
            "ContentBucket",
            LifecycleConfiguration=LifecycleConfiguration(
                Rules=[
                    # not supported by CFN yet:
                    # LifecycleRule(
                    # Transitions=[
                    # LifecycleRuleTransition(
                    # StorageClass='INTELLIGENT_TIERING',
                    # TransitionInDays=1,
                    # ),
                    # ],
                    # Status="Enabled",
                    # ),
                    LifecycleRule(
                        AbortIncompleteMultipartUpload=AbortIncompleteMultipartUpload(
                            DaysAfterInitiation=7
                        ),
                        Status="Enabled",
                    )
                ]
            ),
            LoggingConfiguration=LoggingConfiguration(
                DestinationBucketName=Ref(log_bucket), LogFilePrefix="s3/"
            ),
            BucketEncryption=BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=ServerSideEncryptionByDefault(
                            # Origin Access Identities can't use KMS
                            SSEAlgorithm="AES256"
                        )
                    )
                ]
            ),
            MetricsConfigurations=[MetricsConfiguration(Id="default")],
            PublicAccessBlockConfiguration=PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
        )
    )

    origin_access_identity = template.add_resource(
        CloudFrontOriginAccessIdentity(
            "CloudFrontIdentity",
            CloudFrontOriginAccessIdentityConfig=CloudFrontOriginAccessIdentityConfig(
                Comment=GetAtt(bucket, "Arn")
            ),
        )
    )

    bucket_policy = template.add_resource(
        BucketPolicy(
            "ContentBucketPolicy",
            Bucket=Ref(bucket),
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal(
                            "CanonicalUser",
                            GetAtt(origin_access_identity, "S3CanonicalUserId"),
                        ),
                        Action=[s3.GetObject],
                        Resource=[Join("", [GetAtt(bucket, "Arn"), "/*"])],
                    )
                ],
            ),
        )
    )

    log_bucket_policy = template.add_resource(
        BucketPolicy(
            "LogBucketPolicy",
            Bucket=Ref(log_bucket),
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Sid="Allow CloudFront log delivery",
                        Effect=Allow,
                        Principal=Principal(
                            "CanonicalUser",
                            [
                                # this translates to 162777425019 when saved...
                                "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
                            ],
                        ),
                        Action=[s3.PutObject],
                        Resource=[Join("", [GetAtt(log_bucket, "Arn"), "/*"])],
                    )
                ],
            ),
        )
    )

    certificate_validator_dlq = template.add_resource(
        Queue(
            "CertificateValidatorDLQ",
            MessageRetentionPeriod=int(datetime.timedelta(days=14).total_seconds()),
            KmsMasterKeyId="alias/aws/sqs",
        )
    )

    certificate_validator_role = template.add_resource(
        Role(
            "CertificateValidatorRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect="Allow",
                        Principal=Principal("Service", "lambda.amazonaws.com"),
                        Action=[sts.AssumeRole],
                    )
                ],
            ),
            Policies=[
                PolicyProperty(
                    PolicyName="DLQPolicy",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[sqs.SendMessage],
                                Resource=[GetAtt(certificate_validator_dlq, "Arn")],
                            )
                        ],
                    ),
                )
            ],
            # TODO scope down
            ManagedPolicyArns=[
                "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                "arn:aws:iam::aws:policy/AmazonRoute53FullAccess",
            ],
        )
    )

    certificate_validator_function = template.add_resource(
        Function(
            "CertificateValidatorFunction",
            Runtime="python3.6",
            Handler="index.{}".format(certificate_validator.handler.__name__),
            Code=Code(
                ZipFile=packmodule.pack(inspect.getsource(certificate_validator))
            ),
            MemorySize=256,
            Timeout=300,
            Role=GetAtt(certificate_validator_role, "Arn"),
            DeadLetterConfig=DeadLetterConfig(
                TargetArn=GetAtt(certificate_validator_dlq, "Arn")
            ),
            Environment=Environment(
                Variables={
                    certificate_validator.EnvVars.HOSTED_ZONE_ID.name: Ref(
                        hosted_zone_id
                    )
                }
            ),
        )
    )

    certificate_validator_log_group = template.add_resource(
        LogGroup(
            "CertificateValidatorLogGroup",
            LogGroupName=Join(
                "", ["/aws/lambda/", Ref(certificate_validator_function)]
            ),
            RetentionInDays=Ref(log_retention_days),
        )
    )

    certificate_validator_rule = template.add_resource(
        Rule(
            "CertificateValidatorRule",
            EventPattern={
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["acm.amazonaws.com"],
                    "eventName": ["AddTagsToCertificate"],
                    "requestParameters": {
                        "tags": {
                            "key": [certificate_validator_function.title],
                            "value": [GetAtt(certificate_validator_function, "Arn")],
                        }
                    },
                },
            },
            Targets=[
                Target(
                    Id="certificate-validator-lambda",
                    Arn=GetAtt(certificate_validator_function, "Arn"),
                )
            ],
            DependsOn=[certificate_validator_log_group],
        )
    )

    certificate_validator_permission = template.add_resource(
        Permission(
            "CertificateValidatorPermission",
            FunctionName=GetAtt(certificate_validator_function, "Arn"),
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=GetAtt(certificate_validator_rule, "Arn"),
        )
    )

    certificate = template.add_resource(
        Certificate(
            "Certificate",
            DomainName=Select(0, Ref(dns_names)),
            SubjectAlternativeNames=Ref(dns_names),  # duplicate first name works fine
            ValidationMethod="DNS",
            Tags=Tags(
                **{
                    certificate_validator_function.title: GetAtt(
                        certificate_validator_function, "Arn"
                    )
                }
            ),
            DependsOn=[certificate_validator_permission],
        )
    )

    edge_hook_role = template.add_resource(
        Role(
            "EdgeHookRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect="Allow",
                        Principal=Principal(
                            "Service",
                            ["lambda.amazonaws.com", "edgelambda.amazonaws.com"],
                        ),
                        Action=[sts.AssumeRole],
                    )
                ],
            ),
            # TODO scope down
            ManagedPolicyArns=[
                "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            ],
        )
    )

    # TODO known issue: no log group capture for replicated lambda
    edge_hook_function = template.add_resource(
        Function(
            "EdgeHookFunction",
            Runtime="nodejs8.10",
            Handler="index.handler",
            Code=Code(
                ZipFile=textwrap.dedent(
                    """
                    'use strict';
                    exports.handler = (event, context, callback) => {
                        var request = event.Records[0].cf.request;
                        request.uri = request.uri.replace(/\/$/, '\/index.html');
                        return callback(null, request);
                    };
                    """
                )
            ),
            MemorySize=128,
            Timeout=3,
            Role=GetAtt(edge_hook_role, "Arn"),
        )
    )
    edge_hook_function_hash = (
        hashlib.sha256(
            json.dumps(edge_hook_function.to_dict(), sort_keys=True).encode("utf-8")
        )
        .hexdigest()[:10]
        .upper()
    )

    edge_hook_version = template.add_resource(
        Version(
            "EdgeHookVersion" + edge_hook_function_hash,
            FunctionName=GetAtt(edge_hook_function, "Arn"),
        )
    )

    distribution = template.add_resource(
        Distribution(
            "ContentDistribution",
            DistributionConfig=DistributionConfig(
                Enabled=True,
                Aliases=If(using_dns_names, Ref(dns_names), NoValue),
                Logging=Logging(
                    Bucket=GetAtt(log_bucket, "DomainName"), Prefix="cloudfront/"
                ),
                DefaultRootObject="index.html",
                Origins=[
                    Origin(
                        Id="default",
                        DomainName=GetAtt(bucket, "DomainName"),
                        S3OriginConfig=S3OriginConfig(
                            OriginAccessIdentity=Join(
                                "",
                                [
                                    "origin-access-identity/cloudfront/",
                                    Ref(origin_access_identity),
                                ],
                            )
                        ),
                    )
                ],
                DefaultCacheBehavior=DefaultCacheBehavior(
                    TargetOriginId="default",
                    Compress=True,
                    ForwardedValues=ForwardedValues(QueryString=False),
                    ViewerProtocolPolicy="redirect-to-https",
                    DefaultTTL=Ref(default_ttl_seconds),
                    LambdaFunctionAssociations=[
                        LambdaFunctionAssociation(
                            EventType="origin-request",
                            LambdaFunctionARN=Ref(edge_hook_version),
                        )
                    ],
                ),
                HttpVersion="http2",
                IPV6Enabled=True,
                ViewerCertificate=If(
                    using_hosted_zone,
                    ViewerCertificate(
                        AcmCertificateArn=Ref(certificate),
                        SslSupportMethod="sni-only",
                        MinimumProtocolVersion=Ref(tls_protocol_version),
                    ),
                    ViewerCertificate(
                        CloudFrontDefaultCertificate=True,
                        MinimumProtocolVersion=Ref(tls_protocol_version),
                    ),
                ),
            ),
            DependsOn=[log_ingester_policy],
        )
    )

    distribution_log_group = template.add_resource(
        LogGroup(
            "DistributionLogGroup",
            LogGroupName=Join("", ["/aws/cloudfront/", Ref(distribution)]),
            RetentionInDays=Ref(log_retention_days),
        )
    )

    bucket_log_group = template.add_resource(
        LogGroup(
            "BucketLogGroup",
            LogGroupName=Join("", ["/aws/s3/", Ref(bucket)]),
            RetentionInDays=Ref(log_retention_days),
        )
    )

    template.add_output(Output("DistributionId", Value=Ref(distribution)))

    template.add_output(
        Output("DistributionDomain", Value=GetAtt(distribution, "DomainName"))
    )

    template.add_output(
        Output(
            "DistributionUrl",
            Value=Join("", ["https://", GetAtt(distribution, "DomainName"), "/"]),
        )
    )

    template.add_output(Output("ContentBucketArn", Value=GetAtt(bucket, "Arn")))

    return template


def get_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--minify", action="store_true", default=False)
    return parser.parse_args(argv)


def main(argv=None):
    args = get_args(argv)
    json_kwargs = {"sort_keys": True}
    if args.minify:
        json_kwargs.update({"indent": None, "separators": (",", ":")})
    print(create_template().to_json(**json_kwargs))


if __name__ == "__main__":
    main()
