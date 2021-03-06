from awacs import cloudformation, logs, s3, sns, sqs, sts
from awacs.aws import Allow, PolicyDocument, Principal, Statement
from troposphere import (
    AccountId,
    And,
    AWSProperty,
    Condition,
    Equals,
    FindInMap,
    GetAtt,
    If,
    Join,
    NoValue,
    Not,
    Or,
    Output,
    Parameter,
    Partition,
    Ref,
    Region,
    Select,
    StackName,
    Tags,
    Template,
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
    NotificationConfiguration,
    PublicAccessBlockConfiguration,
    ServerSideEncryptionByDefault,
    ServerSideEncryptionRule,
)
from troposphere.awslambda import (
    Code,
    DeadLetterConfig,
    Environment,
    Function,
    Permission,
    Version,
)
from troposphere.certificatemanager import Certificate
from troposphere.cloudformation import (
    StackSet,
    OperationPreferences,
    Parameter as StackSetParameter,
    StackInstances,
    WaitConditionHandle,
    DeploymentTargets,
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
from troposphere.events import Rule, Target
from troposphere.iam import PolicyProperty, PolicyType, Role
from troposphere.logs import LogGroup
from troposphere.sqs import Queue

import datetime
import hashlib
import inspect
import json
import textwrap


from . import certificate_validator, edge_hook, log_ingest


CLOUDWATCH_LOGS_RETENTION_OPTIONS = [
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
]
PYTHON_RUNTIME = "python3.8"


class OwnershipControlsRule(AWSProperty):
    props = {"ObjectOwnership": (str, False)}


class OwnershipControls(AWSProperty):
    props = {"Rules": ([OwnershipControlsRule], True)}


class Bucket(Bucket):
    props = {**Bucket.props, "OwnershipControls": (OwnershipControls, False)}


def add_condition(template, name, condition):
    template.add_condition(name, condition)
    return name


def add_mapping(template, name, mapping):
    template.add_mapping(name, mapping)
    return name


def create_log_group_template():
    template = Template(Description="Child stack to maintain Lambda@Edge log groups")

    log_group_name = template.add_parameter(Parameter("LogGroupName", Type="String"))
    log_retention_days = template.add_parameter(
        Parameter(
            "LogRetentionDays",
            Type="Number",
            Description="Days to keep Lambda@Edge logs. 0 means indefinite retention.",
            AllowedValues=[0] + CLOUDWATCH_LOGS_RETENTION_OPTIONS,
        )
    )

    retention_defined = add_condition(
        template, "RetentionDefined", Not(Equals(Ref(log_retention_days), 0))
    )

    template.add_resource(
        LogGroup(
            "EdgeLambdaLogGroup",
            LogGroupName=Ref(log_group_name),
            RetentionInDays=If(retention_defined, Ref(log_retention_days), NoValue),
        )
    )

    return template


def create_template():
    template = Template(
        Description=(
            "Static website hosted with S3 and CloudFront. "
            "https://github.com/schlarpc/overengineered-cloudfront-s3-static-website"
        )
    )

    partition_config = add_mapping(
        template,
        "PartitionConfig",
        {
            "aws": {
                # the region with the control plane for CloudFront, IAM, Route 53, etc
                "PrimaryRegion": "us-east-1",
                # assume that Lambda@Edge replicates to all default enabled regions, and that
                # future regions will be opt-in. generated with AWS CLI:
                # aws ec2 describe-regions --all-regions --query "Regions[?OptInStatus=='opt-in-not-required'].RegionName|sort(@)"
                "DefaultRegions": [
                    "ap-northeast-1",
                    "ap-northeast-2",
                    "ap-south-1",
                    "ap-southeast-1",
                    "ap-southeast-2",
                    "ca-central-1",
                    "eu-central-1",
                    "eu-north-1",
                    "eu-west-1",
                    "eu-west-2",
                    "eu-west-3",
                    "sa-east-1",
                    "us-east-1",
                    "us-east-2",
                    "us-west-1",
                    "us-west-2",
                ],
            },
            # this doesn't actually work, because Lambda@Edge isn't supported in aws-cn
            "aws-cn": {
                "PrimaryRegion": "cn-north-1",
                "DefaultRegions": ["cn-north-1", "cn-northwest-1"],
            },
        },
    )

    acm_certificate_arn = template.add_parameter(
        Parameter(
            "AcmCertificateArn",
            Description="Existing ACM certificate to use for serving TLS. Overrides HostedZoneId.",
            Type="String",
            AllowedPattern="(arn:[^:]+:acm:[^:]+:[^:]+:certificate/.+|)",
            Default="",
        )
    )

    hosted_zone_id = template.add_parameter(
        Parameter(
            "HostedZoneId",
            Description="Existing Route 53 zone to use for validating a new TLS certificate.",
            Type="String",
            AllowedPattern="(Z[A-Z0-9]+|)",
            Default="",
        )
    )

    dns_names = template.add_parameter(
        Parameter(
            "DomainNames",
            Description="Comma-separated list of additional domain names to serve.",
            Type="CommaDelimitedList",
            Default="",
        )
    )

    tls_protocol_version = template.add_parameter(
        Parameter(
            "TlsProtocolVersion",
            Description="CloudFront TLS security policy; see https://amzn.to/2DR91Xq for details.",
            Type="String",
            Default="TLSv1.2_2019",
        )
    )

    log_retention_days = template.add_parameter(
        Parameter(
            "LogRetentionDays",
            Description="Days to keep CloudFront, S3, and Lambda logs. 0 means indefinite retention.",
            Type="Number",
            AllowedValues=[0] + CLOUDWATCH_LOGS_RETENTION_OPTIONS,
            Default=365,
        )
    )

    default_ttl_seconds = template.add_parameter(
        Parameter(
            "DefaultTtlSeconds",
            Description="Cache time-to-live when not set by S3 object headers.",
            Type="Number",
            Default=int(datetime.timedelta(minutes=5).total_seconds()),
        )
    )

    enable_price_class_hack = template.add_parameter(
        Parameter(
            "EnablePriceClassHack",
            Description="Cut your bill in half with this one weird trick.",
            Type="String",
            Default="false",
            AllowedValues=["true", "false"],
        )
    )

    retention_defined = add_condition(
        template, "RetentionDefined", Not(Equals(Ref(log_retention_days), 0))
    )

    using_price_class_hack = add_condition(
        template, "UsingPriceClassHack", Equals(Ref(enable_price_class_hack), "true")
    )

    using_acm_certificate = add_condition(
        template, "UsingAcmCertificate", Not(Equals(Ref(acm_certificate_arn), ""))
    )

    using_hosted_zone = add_condition(
        template, "UsingHostedZone", Not(Equals(Ref(hosted_zone_id), ""))
    )

    using_certificate = add_condition(
        template,
        "UsingCertificate",
        Or(Condition(using_acm_certificate), Condition(using_hosted_zone)),
    )

    should_create_certificate = add_condition(
        template,
        "ShouldCreateCertificate",
        And(Condition(using_hosted_zone), Not(Condition(using_acm_certificate))),
    )

    using_dns_names = add_condition(
        template, "UsingDnsNames", Not(Equals(Select(0, Ref(dns_names)), ""))
    )

    is_primary_region = "IsPrimaryRegion"
    template.add_condition(
        is_primary_region,
        Equals(Region, FindInMap(partition_config, Partition, "PrimaryRegion")),
    )

    precondition_region_is_primary = template.add_resource(
        WaitConditionHandle(
            "PreconditionIsPrimaryRegionForPartition", Condition=is_primary_region,
        )
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
            Runtime=PYTHON_RUNTIME,
            Handler="index.{}".format(log_ingest.handler.__name__),
            Code=Code(ZipFile=inspect.getsource(log_ingest)),
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
            # S3 requires this ACL (regardless of bucket policy) or s3:PutBucketLogging fails.
            # When the CloudFront distribution is created, it adds an additional bucket ACL.
            # That ACL is not possible to model in CloudFormation.
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
            OwnershipControls=OwnershipControls(
                Rules=[OwnershipControlsRule(ObjectOwnership="BucketOwnerPreferred")],
            ),
            PublicAccessBlockConfiguration=PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
            DependsOn=[log_ingester_permission],
        )
    )

    log_ingester_log_group = template.add_resource(
        LogGroup(
            "LogIngesterLogGroup",
            LogGroupName=Join("", ["/aws/lambda/", Ref(log_ingester)]),
            RetentionInDays=If(retention_defined, Ref(log_retention_days), NoValue),
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
            OwnershipControls=OwnershipControls(
                Rules=[OwnershipControlsRule(ObjectOwnership="BucketOwnerPreferred")],
            ),
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
                    ),
                ],
            ),
        )
    )

    # Not strictly necessary, as ACLs should take care of this access. However, CloudFront docs
    # state "In some circumstances [...] S3 resets permissions on the bucket to the default value",
    # and this allows logging to work without any ACLs in place.
    log_bucket_policy = template.add_resource(
        BucketPolicy(
            "LogBucketPolicy",
            Bucket=Ref(log_bucket),
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "delivery.logs.amazonaws.com"),
                        Action=[s3.PutObject],
                        Resource=[
                            Join("/", [GetAtt(log_bucket, "Arn"), "cloudfront", "*"])
                        ],
                    ),
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "delivery.logs.amazonaws.com"),
                        Action=[s3.ListBucket],
                        Resource=[Join("/", [GetAtt(log_bucket, "Arn")])],
                    ),
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "s3.amazonaws.com"),
                        Action=[s3.PutObject],
                        Resource=[Join("/", [GetAtt(log_bucket, "Arn"), "s3", "*"])],
                    ),
                ],
            ),
        )
    )

    certificate_validator_dlq = template.add_resource(
        Queue(
            "CertificateValidatorDLQ",
            MessageRetentionPeriod=int(datetime.timedelta(days=14).total_seconds()),
            KmsMasterKeyId="alias/aws/sqs",
            Condition=should_create_certificate,
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
                "arn:aws:iam::aws:policy/AWSCertificateManagerReadOnly",
            ],
            Condition=should_create_certificate,
        )
    )

    certificate_validator_function = template.add_resource(
        Function(
            "CertificateValidatorFunction",
            Runtime=PYTHON_RUNTIME,
            Handler="index.{}".format(certificate_validator.handler.__name__),
            Code=Code(ZipFile=inspect.getsource(certificate_validator)),
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
            Condition=should_create_certificate,
        )
    )

    certificate_validator_log_group = template.add_resource(
        LogGroup(
            "CertificateValidatorLogGroup",
            LogGroupName=Join(
                "", ["/aws/lambda/", Ref(certificate_validator_function)]
            ),
            RetentionInDays=If(retention_defined, Ref(log_retention_days), NoValue),
            Condition=should_create_certificate,
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
            Condition=should_create_certificate,
        )
    )

    certificate_validator_permission = template.add_resource(
        Permission(
            "CertificateValidatorPermission",
            FunctionName=GetAtt(certificate_validator_function, "Arn"),
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=GetAtt(certificate_validator_rule, "Arn"),
            Condition=should_create_certificate,
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
            Condition=should_create_certificate,
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
        )
    )

    edge_hook_function = template.add_resource(
        Function(
            "EdgeHookFunction",
            Runtime=PYTHON_RUNTIME,
            Handler="index.handler",
            Code=Code(ZipFile=inspect.getsource(edge_hook)),
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

    replica_log_group_name = Join(
        "/",
        [
            "/aws/lambda",
            Join(
                ".",
                [
                    FindInMap(partition_config, Partition, "PrimaryRegion"),
                    Ref(edge_hook_function),
                ],
            ),
        ],
    )

    edge_hook_role_policy = template.add_resource(
        PolicyType(
            "EdgeHookRolePolicy",
            PolicyName="write-logs",
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
                                    "*",
                                    AccountId,
                                    "log-group",
                                    replica_log_group_name,
                                    "log-stream",
                                    "*",
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            Roles=[Ref(edge_hook_role)],
        )
    )

    stack_set_administration_role = template.add_resource(
        Role(
            "StackSetAdministrationRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "cloudformation.amazonaws.com"),
                        Action=[sts.AssumeRole],
                    ),
                ],
            ),
        )
    )

    stack_set_execution_role = template.add_resource(
        Role(
            "StackSetExecutionRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal(
                            "AWS", GetAtt(stack_set_administration_role, "Arn")
                        ),
                        Action=[sts.AssumeRole],
                    ),
                ],
            ),
            Policies=[
                PolicyProperty(
                    PolicyName="create-stackset-instances",
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[
                                    cloudformation.DescribeStacks,
                                    logs.DescribeLogGroups,
                                ],
                                Resource=["*"],
                            ),
                            # stack instances communicate with the CFN service via SNS
                            Statement(
                                Effect=Allow,
                                Action=[sns.Publish],
                                NotResource=[
                                    Join(
                                        ":",
                                        ["arn", Partition, "sns", "*", AccountId, "*"],
                                    )
                                ],
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    logs.CreateLogGroup,
                                    logs.DeleteLogGroup,
                                    logs.PutRetentionPolicy,
                                    logs.DeleteRetentionPolicy,
                                ],
                                Resource=[
                                    Join(
                                        ":",
                                        [
                                            "arn",
                                            Partition,
                                            "logs",
                                            "*",
                                            AccountId,
                                            "log-group",
                                            replica_log_group_name,
                                            "log-stream",
                                            "",
                                        ],
                                    ),
                                ],
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    cloudformation.CreateStack,
                                    cloudformation.DeleteStack,
                                    cloudformation.UpdateStack,
                                ],
                                Resource=[
                                    Join(
                                        ":",
                                        [
                                            "arn",
                                            Partition,
                                            "cloudformation",
                                            "*",
                                            AccountId,
                                            Join(
                                                "/",
                                                [
                                                    "stack",
                                                    Join(
                                                        "-",
                                                        ["StackSet", StackName, "*"],
                                                    ),
                                                ],
                                            ),
                                        ],
                                    )
                                ],
                            ),
                        ],
                    ),
                ),
            ],
        )
    )

    stack_set_administration_role_policy = template.add_resource(
        PolicyType(
            "StackSetAdministrationRolePolicy",
            PolicyName="assume-execution-role",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[sts.AssumeRole],
                        Resource=[GetAtt(stack_set_execution_role, "Arn")],
                    ),
                ],
            ),
            Roles=[Ref(stack_set_administration_role)],
        )
    )

    edge_log_groups = template.add_resource(
        StackSet(
            "EdgeLambdaLogGroupStackSet",
            AdministrationRoleARN=GetAtt(stack_set_administration_role, "Arn"),
            ExecutionRoleName=Ref(stack_set_execution_role),
            StackSetName=Join("-", [StackName, "EdgeLambdaLogGroup"]),
            PermissionModel="SELF_MANAGED",
            Description="Multi-region log groups for Lambda@Edge replicas",
            Parameters=[
                StackSetParameter(
                    ParameterKey="LogGroupName", ParameterValue=replica_log_group_name,
                ),
                StackSetParameter(
                    ParameterKey="LogRetentionDays",
                    ParameterValue=Ref(log_retention_days),
                ),
            ],
            OperationPreferences=OperationPreferences(
                FailureToleranceCount=0, MaxConcurrentPercentage=100,
            ),
            StackInstancesGroup=[
                StackInstances(
                    DeploymentTargets=DeploymentTargets(Accounts=[AccountId]),
                    Regions=FindInMap(partition_config, Partition, "DefaultRegions"),
                )
            ],
            TemplateBody=create_log_group_template().to_json(indent=None),
            DependsOn=[stack_set_administration_role_policy],
        )
    )

    price_class_distribution = template.add_resource(
        Distribution(
            "PriceClassDistribution",
            DistributionConfig=DistributionConfig(
                Comment="Dummy distribution used for price class hack",
                DefaultCacheBehavior=DefaultCacheBehavior(
                    TargetOriginId="default",
                    ViewerProtocolPolicy="allow-all",
                    ForwardedValues=ForwardedValues(QueryString=False),
                ),
                Enabled=True,
                Origins=[Origin(Id="default", DomainName=GetAtt(bucket, "DomainName"))],
                IPV6Enabled=True,
                ViewerCertificate=ViewerCertificate(CloudFrontDefaultCertificate=True),
                PriceClass="PriceClass_All",
            ),
            Condition=using_price_class_hack,
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
                ViewerCertificate=ViewerCertificate(
                    AcmCertificateArn=If(
                        using_acm_certificate,
                        Ref(acm_certificate_arn),
                        If(using_hosted_zone, Ref(certificate), NoValue),
                    ),
                    SslSupportMethod=If(using_certificate, "sni-only", NoValue),
                    CloudFrontDefaultCertificate=If(using_certificate, NoValue, True),
                    MinimumProtocolVersion=Ref(tls_protocol_version),
                ),
                PriceClass=If(
                    using_price_class_hack, "PriceClass_100", "PriceClass_All"
                ),
            ),
            DependsOn=[
                bucket_policy,
                log_ingester_policy,
                edge_log_groups,
                precondition_region_is_primary,
            ],
        )
    )

    distribution_log_group = template.add_resource(
        LogGroup(
            "DistributionLogGroup",
            LogGroupName=Join("", ["/aws/cloudfront/", Ref(distribution)]),
            RetentionInDays=If(retention_defined, Ref(log_retention_days), NoValue),
        )
    )

    bucket_log_group = template.add_resource(
        LogGroup(
            "BucketLogGroup",
            LogGroupName=Join("", ["/aws/s3/", Ref(bucket)]),
            RetentionInDays=If(retention_defined, Ref(log_retention_days), NoValue),
        )
    )

    template.add_output(Output("DistributionId", Value=Ref(distribution)))

    template.add_output(
        Output("DistributionDomain", Value=GetAtt(distribution, "DomainName"))
    )

    template.add_output(
        Output(
            "DistributionDnsTarget",
            Value=If(
                using_price_class_hack,
                GetAtt(price_class_distribution, "DomainName"),
                GetAtt(distribution, "DomainName"),
            ),
        )
    )

    template.add_output(
        Output(
            "DistributionUrl",
            Value=Join("", ["https://", GetAtt(distribution, "DomainName"), "/"]),
        )
    )

    template.add_output(Output("ContentBucketArn", Value=GetAtt(bucket, "Arn")))

    return template
