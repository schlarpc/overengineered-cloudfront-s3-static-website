import boto3
import functools
import json
import urllib.parse


@functools.lru_cache()
def create_s3_client(region_name):
    return boto3.client("s3", region_name=region_name)


def get_bucket_name_from_domain(domain):
    # TODO robustify
    return domain.split(".")[0]


def generate_redirect(status_code: str, location, *, headers=None, body=None):
    redirect = {
        "status": status_code,
        "headers": {**(headers or {}), **{"location": [{"value": location}]}},
    }
    if body is not None:
        if isinstance(body, str):
            redirect["body"] = body
        elif isinstance(body, bytes):
            redirect.update(
                {
                    "body": base64.b64encode(body).decode("utf-8"),
                    "bodyEncoding": "base64",
                }
            )
    return redirect


def process_routing_rule(routing_rule, request):
    if "ReplaceKeyPrefixWith" in routing_rule["Redirect"]:
        path = request["uri"].replace(
            routing_rule["Condition"]["KeyPrefixEquals"],
            routing_rule["Redirect"]["ReplaceKeyPrefixWith"],
            1,
        )
    elif "ReplaceKeyWith" in routing_rule["Redirect"]:
        path = routing_rule["Redirect"]["ReplaceKeyWith"]
    else:
        path = request["uri"]
    return generate_redirect(
        routing_rule["Redirect"].get("HttpRedirectCode", "301"),
        urllib.parse.urlunsplit(
            (
                routing_rule["Redirect"].get("Protocol", "http"),
                routing_rule["Redirect"]["HostName"],
                path,
                request["querystring"],
                "",
            )
        ),
    )

def handle_origin_request(event):
    s3 = create_s3_client(event["request"]["origin"]["s3"]["region"])
    bucket_name = get_bucket_name_from_domain(event["request"]["origin"]["s3"]["domainName"])
    request_key = event["request"]["uri"][1:]
    website_config = s3.get_bucket_website(Bucket=bucket_name)

    if "RedirectAllRequestsTo" in website_config:
        return generate_redirect(
            "301",
            urllib.parse.urlunsplit(
                (
                    website_config["RedirectAllRequestsTo"].get("Protocol", "http"),
                    website_config["RedirectAllRequestsTo"]["HostName"],
                    event["request"]["uri"],
                    event["request"]["querystring"],
                    "",
                )
            ),
        )

    for routing_rule in website_config.get("RoutingRules", []):
        # rules with HTTP status code conditions have to be handled in origin-response
        condition = routing_rule.get("Condition", {})
        if not set(condition.keys()) <= {"KeyPrefixEquals"}:
            break
        if not request_key.startswith(condition.get("KeyPrefixEquals", "")):
            continue
        return process_routing_rule(routing_rule, event["request"])

    if event["request"]["uri"].endswith("/"):
        event["request"]["uri"] += website_config["IndexDocument"]["Suffix"]

    # stop user from doing things like ListObjects, GetObjectAcl, etc
    event["request"]["querystring"] = ""

    return event["request"]

def handle_origin_response(event):
    s3 = create_s3_client(event["request"]["origin"]["s3"]["region"])
    bucket_name = get_bucket_name_from_domain(event["request"]["origin"]["s3"]["domainName"])
    request_key = event["request"]["uri"][1:]
    website_config = s3.get_bucket_website(Bucket=bucket_name)

    read_only_headers = {
        k: v
        for k, v in event["response"]["headers"].items()
        if k in {"transfer-encoding", "via"}
    }

    for header in event["response"]["headers"].get("x-amz-website-redirect-location", []):
        return generate_redirect("301", header["value"], body="")

    if event["response"]["status"] == "404" and not request_key.endswith("/"):
        try:
            response = s3.head_object(
                Bucket=bucket_name,
                Key=request_key + "/" + website_config["IndexDocument"]["Suffix"],
            )
            return generate_redirect(
                "302", event["request"]["uri"] + "/", headers=read_only_headers
            )
        except s3.exceptions.ClientError:
            pass

    if 400 <= int(event["response"]["status"]) <= 499 and "ErrorDocument" in website_config:
        try:
            response = s3.get_object(
                Bucket=bucket_name,
                Key=website_config["ErrorDocument"]["Key"],
            )
            if "WebsiteRedirectLocation" in response:
                return generate_redirect(
                    "301", response["WebsiteRedirectLocation"], headers=read_only_headers
                )
            else:
                event["response"]["body"] = base64.b64encode(response["Body"].read())
                event["response"]["bodyEncoding"] = "base64"
                return event["response"]
        except s3.exceptions.ClientError:
            pass

    for routing_rule in website_config.get("RoutingRules", []):
        condition = routing_rule.get("Condition", {})
        if not set(condition.keys()) <= {"KeyPrefixEquals", "HttpErrorCodeReturnedEquals"}:
            continue
        if not request_key.startswith(condition.get("KeyPrefixEquals", "")):
            continue
        if "HttpErrorCodeReturnedEquals" in condition and event["response"]["status"] != condition["HttpErrorCodeReturnedEquals"]:
            continue
        return process_routing_rule(routing_rule, event["request"])

    return event["response"]

def handler(raw_event, _context):
    event = raw_event["Records"][0]["cf"]
    handlers = {"origin-request": handle_origin_request, "origin-response": handle_origin_response}
    return handlers[event["config"]["eventType"]](event)
