# overengineered-cloudfront-s3-static-website

This aims to be the best damn static website you can host on AWS without a server.
Includes automatic certificate issuance with Amazon Certificate Manager and Route 53,
default index.html serving on all directories, searchable logs, modern networking, and more.

All services used by default are either included in the AWS free tier or have low cost
usage-based billing, making it suitable for projects of any size.

## Usage

To generate the CloudFormation template:

```
env PYTHONPATH=src python3 -m overengineered_cloudfront_s3_static_website > template.json

# or, using a flakes-compatible install of the Nix package manager:
nix run . > template.json
```


To deploy a basic website with a CloudFront-generated domain name:

```
aws cloudformation deploy --region us-east-1 --stack-name basic-distribution \
    --template-file template.json --capabilities CAPABILITY_IAM
```

To deploy a website with automatic TLS certificates (given your DNS is hosted on Route 53):

```
aws cloudformation deploy --region us-east-1 --stack-name automatic-acm-distribution \
    --template-file template.json --capabilities CAPABILITY_IAM \
    --parameter-overrides DomainNames=example.com,www.example.com HostedZoneId=Z1XYZ12XYZ1XYZ
```

To deploy a website with an existing ACM certificate:

```
aws cloudformation deploy --region us-east-1 --stack-name existing-acm-distribution \
    --template-file template.json --capabilities CAPABILITY_IAM \
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

* No custom HTTP error pages
    * i.e. https://docs.aws.amazon.com/AmazonS3/latest/userguide/CustomErrorDocSupport.html
* No rule-based redirect support
    * i.e. https://docs.aws.amazon.com/AmazonS3/latest/userguide/how-to-page-redirect.html
    * Per-object redirects using `x-amz-website-redirect-location` are implemented
* The index document name cannot be configured, and is always `index.html`
    * i.e. https://docs.aws.amazon.com/AmazonS3/latest/userguide/IndexDocumentSupport.html
* Directory URLs must end in "/" to get index.html retrieval behavior
    * e.g. `http://example.com/foo` will not return the content at `foo/index.html`
* No metric/alarm dashboard
    * This costs extra, so probably should be disabled by default if implemented
* No usage of KMS encryption for S3 buckets or CloudWatch Logs
    * This requires customer-managed KMS keys, which cost extra; this is a low-priority TODO
* Access logs should be converted to JSON format for easier querying
