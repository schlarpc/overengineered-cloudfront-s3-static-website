# overengineered-cloudfront-s3-static-website

This aims to be the best damn static website you can host on AWS without a server.
Includes automatic certificate issuance with ACM and Route 53, default index.html serving,
searchable logs, modern networking, and more.

## Usage

To generate the CloudFormation template:

`python3 -m overengineered_cloudfront_s3_static_website`

To deploy a basic CloudFront distribution:

```
aws cloudformation --region us-east-1 deploy --stack-name basic-distribution \
    --template-file <(python3 -m overengineered_cloudfront_s3_static_website) \
    --capabilities CAPABILITY_IAM
```

To deploy a CloudFront distribution with automatic TLS certificates from ACM:

```
aws cloudformation --region us-east-1 deploy --stack-name automatic-acm-distribution \
    --template-file <(python3 -m overengineered_cloudfront_s3_static_website) \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides DomainNames=example.com,www.example.com HostedZoneId=Z1XYZ12XYZ1XYZ \
```

To deploy a CloudFront distribution with an existing ACM certificate:

```
aws cloudformation --region us-east-1 deploy --stack-name existing-acm-distribution \
    --template-file <(python3 -m overengineered_cloudfront_s3_static_website) \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides DomainNames=example.com,www.example.com \
    AcmCertificateArn=arn:aws:acm:us-east-1:123412341234:certificate/d3ad-b33f
```

The template parameters also include some extra settings:

* `TlsProtocolVersion` - TLS protocol and cipher suite selection
* `LogRetentionDays` - days to keep logs in CloudWatch Logs
* `DefaultTtlSeconds` - default edge cache timeout


## Limitations / To-do

* No custom HTTP error pages or header-based redirect support
* No metric/alarm dashboard (can be costly, so probably should be disabled by default?)
* No registration of distribution as an alias record in Route 53
* No usage of KMS encryption for S3 buckets (AWS limitations)
* Some Lambda execution policies are overly broad
* Log groups for Lambda@Edge replicated functions are not captured in the template
