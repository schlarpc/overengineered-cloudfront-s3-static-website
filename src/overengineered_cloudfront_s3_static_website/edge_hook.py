import re


def handler(event, context):
    request = event["Records"][0]["cf"]["request"]
    request["uri"] = re.sub(r"/$", "/index.html", request["uri"])
    return request
