import base64
import datetime
import gzip
import inspect
import pathlib

from awacs import logs, s3, sqs, sts
from awacs.aws import (
    Allow,
    Bool,
    Condition as StatementCondition,
    Deny,
    Everybody,
    PolicyDocument,
    Principal,
    SecureTransport,
    SourceAccount,
    Statement,
    StringEquals,
)
from troposphere import (
    AccountId,
    And,
    AWSHelperFn,
    Condition,
    Equals,
    FindInMap,
    GetAtt,
    If,
    Join,
    Not,
    NoValue,
    Or,
    Output,
    Parameter,
    Partition,
    Ref,
    Region,
    Select,
    Split,
    StackName,
    Template,
)
from troposphere.awslambda import Code, DeadLetterConfig, Function, Permission
from troposphere.certificatemanager import Certificate, DomainValidationOption
from troposphere.cloudformation import WaitConditionHandle
from troposphere.cloudfront import (
    CacheCookiesConfig,
    CacheHeadersConfig,
    CachePolicy,
    CachePolicyConfig,
    CacheQueryStringsConfig,
    CloudFrontOriginAccessIdentity,
    CloudFrontOriginAccessIdentityConfig,
    DefaultCacheBehavior,
    Distribution,
    DistributionConfig,
    Function as CloudFrontFunction,
    FunctionAssociation,
    FunctionConfig,
    Logging,
    Origin,
    OriginRequestCookiesConfig,
    OriginRequestHeadersConfig,
    OriginRequestPolicy,
    OriginRequestPolicyConfig,
    OriginRequestQueryStringsConfig,
    ParametersInCacheKeyAndForwardedToOrigin,
    S3OriginConfig,
    ViewerCertificate,
)
from troposphere.iam import PolicyProperty, PolicyType, Role
from troposphere.logs import LogGroup
from troposphere.route53 import AliasTarget, RecordSet, RecordSetGroup
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
    OwnershipControls,
    OwnershipControlsRule,
    PublicAccessBlockConfiguration,
    ServerSideEncryptionByDefault,
    ServerSideEncryptionRule,
)
from troposphere.sqs import Queue

from . import log_ingest

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
# TODO make precondition or parameter pattern for domain count
MAX_DOMAIN_NAMES = 10  # default quota for ACM, maxes out at 100
PYTHON_RUNTIME = "python3.8"


class NotificationConfiguration(NotificationConfiguration):
    props = {
        **NotificationConfiguration.props,
        "EventBridgeConfiguration": (dict, False),
    }


class ListChecker(AWSHelperFn):
    def __init__(self, template, name, items, *, delimiter=",", default_value=""):
        self._template = template
        self._name = name
        self._items = items
        self._delimiter = delimiter
        self._default_value = default_value

    def _extract_value(self, index):
        padding = self._delimiter.join([self._default_value] * (index + 1))
        joined = Join(self._delimiter, [Join(self._delimiter, self._items), padding])
        exploded = Split(self._delimiter, joined)
        return Select(index, exploded)

    def _add_existence_condition(self, index):
        condition_name = f"{self._name}ListIdx{index}Exists"
        self._template.add_condition(
            condition_name, Not(Equals(self._extract_value(index), self._default_value))
        )
        return condition_name

    def exists(self, index) -> str:
        return self._add_existence_condition(index)


def add_condition(template, name, condition):
    template.add_condition(name, condition)
    return name


def add_mapping(template, name, mapping):
    template.add_mapping(name, mapping)
    return name


def read_static_file(filename, mode="r"):
    with (pathlib.Path(__file__).parent / "static" / filename).open(mode) as f:
        return f.read()


def pack_python_module(source: str) -> str:
    encoded = base64.b85encode(gzip.compress(source.encode("utf-8"))).decode("utf-8")
    return f"import base64,gzip;exec(gzip.decompress(base64.b85decode('{encoded}')))"


def generate_enforced_tls_statement(bucket_arn) -> Statement:
    return Statement(
        Effect=Deny,
        Principal=Principal(Everybody),
        Action=[s3.Action("*")],
        Resource=[
            bucket_arn,
            Join("/", [bucket_arn, "*"]),
        ],
        Condition=StatementCondition(
            Bool(SecureTransport, False),
        ),
    )


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
                "CloudFrontHostedZoneId": "Z2FDTNDATAQYW2",
            },
            # no idea if CloudFront Functions work in China
            "aws-cn": {
                "PrimaryRegion": "cn-north-1",
                "CloudFrontHostedZoneId": "Z3RFFRIM2A3IF5",
            },
        },
    )

    acm_certificate_arn = template.add_parameter(
        Parameter(
            "AcmCertificateArn",
            Description=" ".join(
                (
                    "Existing ACM certificate to use for serving TLS.",
                    "If left blank while HostedZoneId is set, a new certificate will be created.",
                )
            ),
            Type="String",
            AllowedPattern="(arn:[^:]+:acm:[^:]+:[^:]+:certificate/.+|)",
            Default="",
        )
    )

    hosted_zone_id = template.add_parameter(
        Parameter(
            "HostedZoneId",
            Description=" ".join(
                (
                    "Existing Route 53 zone for the domains specified in DomainNames.",
                    "Used for validating new TLS certificates and creating DNS records.",
                )
            ),
            Type="String",
            AllowedPattern="(Z[A-Z0-9]+|)",
            Default="",
        )
    )

    dns_names = template.add_parameter(
        Parameter(
            "DomainNames",
            Description=" ".join(
                (
                    "Comma-separated list of additional domain names to serve.",
                    f"Up to {MAX_DOMAIN_NAMES} domains can be specified.",
                )
            ),
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

    create_dns_records = template.add_parameter(
        Parameter(
            "CreateDnsRecords",
            Description=" ".join(
                (
                    "Create A and AAAA records pointing to CloudFront in Route 53.",
                    "This operation will fail if any of those records already exist.",
                    "Requires DomainNames and HostedZoneId to be set.",
                )
            ),
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

    should_create_dns_records = add_condition(
        template,
        "ShouldCreateDnsRecords",
        And(
            Equals(Ref(create_dns_records), "true"),
            Condition(using_dns_names),
            Condition(using_hosted_zone),
        ),
    )

    is_primary_region = "IsPrimaryRegion"
    template.add_condition(
        is_primary_region,
        Equals(Region, FindInMap(partition_config, Partition, "PrimaryRegion")),
    )

    precondition_region_is_primary = template.add_resource(
        WaitConditionHandle(
            "PreconditionIsPrimaryRegionForPartition",
            Condition=is_primary_region,
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
                    PolicyName="ForwardToDLQ",
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
            Code=Code(ZipFile=pack_python_module(inspect.getsource(log_ingest))),
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
                # BucketOwnerEnforced is not supported for CloudFront logs, see https://go.aws/2ZJlydg
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

    log_bucket_policy = template.add_resource(
        BucketPolicy(
            "LogBucketPolicy",
            Bucket=Ref(log_bucket),
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    # The next statement is not strictly necessary, as CloudFront automatically
                    # creates an ACL to allow log delivery. However, this statement allows logging
                    # to continue working without that ACL, and CloudFront docs warn that
                    # "In some circumstances, [...] S3 resets [ACLs] on the bucket to the default value".
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "delivery.logs.amazonaws.com"),
                        Action=[s3.PutObject],
                        Resource=[
                            Join("/", [GetAtt(log_bucket, "Arn"), "cloudfront", "*"])
                        ],
                        Condition=StatementCondition(
                            StringEquals(SourceAccount, AccountId),
                        ),
                    ),
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "logging.s3.amazonaws.com"),
                        Action=[s3.PutObject],
                        Resource=[Join("/", [GetAtt(log_bucket, "Arn"), "s3", "*"])],
                        Condition=StatementCondition(
                            StringEquals(SourceAccount, AccountId),
                        ),
                    ),
                    generate_enforced_tls_statement(GetAtt(log_bucket, "Arn")),
                ],
            ),
        )
    )

    log_ingester_log_group = template.add_resource(
        LogGroup(
            "LogIngesterLogGroup",
            LogGroupName=Join("", ["/aws/lambda/", Ref(log_ingester)]),
            RetentionInDays=If(retention_defined, Ref(log_retention_days), NoValue),
        )
    )

    log_ingester_execution_logs_policy = template.add_resource(
        PolicyType(
            "LogIngesterExecutionLogsPolicy",
            Roles=[Ref(log_ingester_role)],
            PolicyName="WriteExecutionLogs",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                        Resource=[
                            GetAtt(log_ingester_log_group, "Arn"),
                        ],
                    ),
                ],
            ),
        )
    )

    log_ingester_read_web_logs_policy = template.add_resource(
        PolicyType(
            "LogIngesterReadWebLogsPolicy",
            Roles=[Ref(log_ingester_role)],
            PolicyName="ReadWebLogs",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[s3.GetObject],
                        Resource=[Join("/", [GetAtt(log_bucket, "Arn"), "*"])],
                    ),
                ],
            ),
        )
    )

    # these "leaf" nodes of the logging resources need explicit DependsOn statements
    log_ingestion_dependencies = [
        log_bucket_policy,
        log_ingester_execution_logs_policy,
        log_ingester_read_web_logs_policy,
    ]

    bucket = template.add_resource(
        Bucket(
            "ContentBucket",
            LifecycleConfiguration=LifecycleConfiguration(
                Rules=[
                    LifecycleRule(
                        Transitions=[
                            LifecycleRuleTransition(
                                StorageClass="INTELLIGENT_TIERING",
                                TransitionInDays=1,
                            ),
                        ],
                        Status="Enabled",
                    ),
                    LifecycleRule(
                        AbortIncompleteMultipartUpload=AbortIncompleteMultipartUpload(
                            DaysAfterInitiation=7
                        ),
                        Status="Enabled",
                    ),
                ]
            ),
            NotificationConfiguration=NotificationConfiguration(
                EventBridgeConfiguration={},
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
                Rules=[OwnershipControlsRule(ObjectOwnership="BucketOwnerEnforced")],
            ),
            PublicAccessBlockConfiguration=PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
            DependsOn=log_ingestion_dependencies,
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
                    generate_enforced_tls_statement(GetAtt(bucket, "Arn")),
                ],
            ),
        )
    )

    dns_names_checker = ListChecker(template, "DNSNames", Ref(dns_names))

    certificate = template.add_resource(
        Certificate(
            "Certificate",
            DomainName=Select(0, Ref(dns_names)),
            SubjectAlternativeNames=Ref(dns_names),  # duplicate first name works fine
            ValidationMethod="DNS",
            DomainValidationOptions=[
                If(
                    dns_names_checker.exists(idx),
                    DomainValidationOption(
                        DomainName=Select(idx, Ref(dns_names)),
                        HostedZoneId=Ref(hosted_zone_id),
                    ),
                    NoValue,
                )
                for idx in range(MAX_DOMAIN_NAMES)
            ],
            Condition=should_create_certificate,
        )
    )

    cache_policy = template.add_resource(
        CachePolicy(
            "CachePolicy",
            CachePolicyConfig=CachePolicyConfig(
                Name=Join("-", [StackName, "CachePolicy"]),
                DefaultTTL=Ref(default_ttl_seconds),
                MinTTL=0,
                MaxTTL=int(datetime.timedelta(days=365).total_seconds()),
                ParametersInCacheKeyAndForwardedToOrigin=ParametersInCacheKeyAndForwardedToOrigin(
                    EnableAcceptEncodingBrotli=True,
                    EnableAcceptEncodingGzip=True,
                    CookiesConfig=CacheCookiesConfig(
                        CookieBehavior="none",
                    ),
                    HeadersConfig=CacheHeadersConfig(
                        HeaderBehavior="none",
                    ),
                    QueryStringsConfig=CacheQueryStringsConfig(
                        QueryStringBehavior="none",
                    ),
                ),
            ),
        )
    )

    origin_request_policy = template.add_resource(
        OriginRequestPolicy(
            "OriginRequestPolicy",
            OriginRequestPolicyConfig=OriginRequestPolicyConfig(
                Name=Join("-", [StackName, "OriginRequestPolicy"]),
                CookiesConfig=OriginRequestCookiesConfig(
                    CookieBehavior="none",
                ),
                HeadersConfig=OriginRequestHeadersConfig(
                    HeaderBehavior="none",
                ),
                QueryStringsConfig=OriginRequestQueryStringsConfig(
                    QueryStringBehavior="none",
                ),
            ),
        )
    )

    viewer_request_function_name = Join("-", [StackName, "ViewerRequestFunction"])

    template.add_resource(
        LogGroup(
            "ViewerRequestFunctionLogGroup",
            LogGroupName=Join(
                "", ["/aws/cloudfront/function/", viewer_request_function_name]
            ),
            RetentionInDays=If(retention_defined, Ref(log_retention_days), NoValue),
        )
    )

    viewer_request_function = template.add_resource(
        CloudFrontFunction(
            "ViewerRequestFunction",
            Name=viewer_request_function_name,
            FunctionCode=read_static_file("viewer_request.js"),
            AutoPublish=True,
            FunctionConfig=FunctionConfig(
                Comment=viewer_request_function_name,
                Runtime="cloudfront-js-1.0",
            ),
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
                    CachePolicyId=Ref(cache_policy),
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
                    CachePolicyId=Ref(cache_policy),
                    OriginRequestPolicyId=Ref(origin_request_policy),
                    Compress=True,
                    ViewerProtocolPolicy="redirect-to-https",
                    FunctionAssociations=[
                        FunctionAssociation(
                            EventType="viewer-request",
                            FunctionARN=GetAtt(viewer_request_function, "FunctionARN"),
                        ),
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
                precondition_region_is_primary,
                bucket_policy,
            ]
            + log_ingestion_dependencies,
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

    # Since this policy is being added after the distribution and bucket are created,
    # the Lambda function could receive logs before it has permission to write to CloudWatch Logs.
    # This is unlikely due to log delivery delays and Lambda's async invoke redrives,
    # but it's _possible_ to lose log entries that occur before the stack is fully deployed.
    log_ingester_write_web_logs_policy = template.add_resource(
        PolicyType(
            "LogIngesterWriteWebLogsPolicy",
            Roles=[Ref(log_ingester_role)],
            PolicyName="WriteWebLogs",
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                        Resource=[
                            GetAtt(distribution_log_group, "Arn"),
                            GetAtt(bucket_log_group, "Arn"),
                        ],
                    ),
                ],
            ),
        )
    )

    log_ingestion_dependencies = [
        *log_ingestion_dependencies,
        log_ingester_write_web_logs_policy,
    ]

    record_sets = []
    for idx in range(MAX_DOMAIN_NAMES):
        for record_type in ("A", "AAAA"):
            record_sets.append(
                If(
                    dns_names_checker.exists(idx),
                    RecordSet(
                        Name=Select(idx, Ref(dns_names)),
                        Type=record_type,
                        AliasTarget=AliasTarget(
                            DNSName=If(
                                using_price_class_hack,
                                GetAtt(price_class_distribution, "DomainName"),
                                GetAtt(distribution, "DomainName"),
                            ),
                            HostedZoneId=FindInMap(
                                partition_config, Partition, "CloudFrontHostedZoneId"
                            ),
                        ),
                    ),
                    NoValue,
                )
            )

    template.add_resource(
        RecordSetGroup(
            "DnsRecords",
            HostedZoneId=Ref(hosted_zone_id),
            RecordSets=record_sets,
            DependsOn=log_ingestion_dependencies,
            Condition=should_create_dns_records,
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

    template.add_output(Output("ContentBucketName", Value=Ref(bucket)))

    return template
