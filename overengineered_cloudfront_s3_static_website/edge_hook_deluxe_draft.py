

# TODO if path ends in slash, ALWAYS use index document. keys ending in / are ignored

def handle_origin_request(event, _context):
    event = event["Records"][0]["cf"]
    if "RedirectAllRequestsTo" in website_configuration:
        return {
            "status": "301",
            "headers": {
                "location": {
                    "value":
                    "".join((
                        website_configuration["RedirectAllRequestsTo"]["Protocol"] + "://",
                        website_configuration["RedirectAllRequestsTo"]["HostName"],
                        event["request"]["uri"],
                    ))
                }
            }
        }

    # TODO can multiple routing rules apply? or is it just "first match"
    # TODO what happens when condition is empty?
    # TODO what happens when redirect is empty?
    for routing_rule in website_configuration.get("RoutingRules", []):
        if "KeyPrefixEquals" in routing_rule and "HttpErrorCodeReturnedEquals" not in routing_rule:
            pass

def extract_bucket_name_from_origin_domain(request):
    # TODO robustify
    return request["origin"]["s3"]["domainName"].split(".")[0]

def handle_origin_response(event, _context):
    event = event["Records"][0]["cf"]
    for header in event["response"]["headers"].get("x-amz-website-redirect-location", []):
        # TODO this also needs to be done for index and error documents
        return {
            "status": "301",
            "headers": {
                "location": {"value": header["value"]},
            },
        }
    # TODO does this handle root requests correctly?
    # TODO what is the TTL on negative responses from S3? should we change this?
    if event["response"]["status"] == "404":
        # TODO get index document name
        # TODO use safer URL construction
        key = event["request"]["uri"].rstrip("/") + "/" + index_document
        try:
            response = s3.get_object(
                # TODO determine bucket name
                Bucket=extract_bucket_name_from_request(event["request"]),
                Key=key,
                # TODO determine bucket owner
                ExpectedBucketOwner=...,
            )
            if event["request"]["uri"].endswith("/"):
                return {
                    "status": "200",
                    "bodyEncoding": "base64",
                    "body": base64.b64decode(response["Body"].read()).decode("utf-8"),
                }
            else:
                return {
                    "status": "302",
                    "headers": {
                        # TODO is this always a valid location header?
                        "location": {"value": event["request"]["uri"] + "/"},
                    }
                }
        except s3.exceptions.NoSuchKey:
            pass

    elif re.match(r"^4[0-9]{2}$", event["response"]["status"]):
        response = s3.get_object(
            # TODO determine bucket name
            Bucket=...,
            Key=error_document,
            # TODO determine bucket owner
            ExpectedBucketOwner=...,
        )
        return {
            "status": event["response"]["status"],
            "bodyEncoding": "base64",
            "body": base64.b64decode(response["Body"].read()).decode("utf-8"),
        }

    # TODO ordering
    for routing_rule in website_configuration.get("RoutingRules", []):
        if "HttpErrorCodeReturnedEquals" in routing_rule and routing_rule["HttpErrorCodeReturnedEquals"] == event["response"]["status"]:
            pass


    return event["response"]
