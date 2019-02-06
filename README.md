# overengineered-cloudfront-s3-static-website

This aims to be the best damn static website you can host on AWS without a server.
Includes automatic certificate issuance with Amazon Certificate Manager and Route 53,
default index.html serving on all directories, searchable logs, modern networking, and more.

All services used by default are either included in the AWS free tier or have low cost
usage-based billing, making it suitable for projects of any size.

## Usage

To generate the CloudFormation template:

`python3 -m overengineered_cloudfront_s3_static_website`

To deploy a basic website with a CloudFront-generated domain name:

```
aws cloudformation deploy --region us-east-1 --stack-name basic-distribution \
    --template-file <(python3 -m overengineered_cloudfront_s3_static_website) \
    --capabilities CAPABILITY_IAM
```

To deploy a website with automatic TLS certificates (given your DNS is hosted on Route 53):

```
aws cloudformation deploy --region us-east-1 --stack-name automatic-acm-distribution \
    --template-file <(python3 -m overengineered_cloudfront_s3_static_website) \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides DomainNames=example.com,www.example.com HostedZoneId=Z1XYZ12XYZ1XYZ
```

To deploy a website with an existing ACM certificate:

```
aws cloudformation deploy --region us-east-1 --stack-name existing-acm-distribution \
    --template-file <(python3 -m overengineered_cloudfront_s3_static_website) \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides DomainNames=example.com,www.example.com \
    AcmCertificateArn=arn:aws:acm:us-east-1:123412341234:certificate/d3ad-b33f
```

Once the CloudFormation stack is deployed, check the stack outputs for `ContentBucketArn`.
Using the tool of your choice, upload your website content into that bucket and you're good to go.

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
* Stack deletion will fail on the Lambda@Edge function but will succeed after several hours (AWS limitation)
* Directory URLs must end in "/" to get index.html retrieval behavior (e.g http://example.com/foo will not return the content at foo/index.html)
