import pytest
import requests
import boto3
import contextlib
import time
import urllib.parse
import botocore.exceptions

BUCKET = "s3-website-hook-2-contentbucket-4p32bnu0xuhc"
BUCKET_DOMAIN = f"http://{BUCKET}.s3-website.us-east-1.amazonaws.com/"
DISTRO = "https://dp7evxlcmu4c6.cloudfront.net/"


def get(domain, path):
    return requests.get(
        urllib.parse.urljoin(
            domain, path
        ),
        allow_redirects=False,
    )


@contextlib.contextmanager
def bucket_setup(keys, website_configuration=None):
    bucket = boto3.resource("s3").Bucket(BUCKET)
    bucket.objects.delete()
    if website_configuration is None:
        website_configuration = {
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        }
    bucket.Website().put(WebsiteConfiguration=website_configuration)
    for key in keys:
        kwargs = {}
        if isinstance(key, tuple):
            key, kwargs = key
        bucket.put_object(
            Key=key,
            **{"Body": key.encode("utf-8"), **kwargs},
        )
    time.sleep(5)
    yield

@pytest.mark.parametrize('domain', [BUCKET_DOMAIN, DISTRO])
class TestCases:
    def test_indexdocument_bare_key_exists_index_exists(self, domain):
        with bucket_setup(["key", "key/index.html"]):
            response = get(domain, "/key")
            assert response.status_code == 200
            assert response.text == "key"

    def test_indexdocument_bare_key_missing_index_exists(self, domain):
        with bucket_setup(["key/index.html"]):
            response = get(domain, "/key")
            assert response.status_code == 302
            assert response.headers["location"] == "/key/"

    def test_indexdocument_bare_key_missing_index_exists_query_string_meaningful(self, domain):
        with bucket_setup(["key/index.html"]):
            response = get(domain, "/key?acl")
            assert response.status_code == 302
            assert response.headers["location"] == "/key/"

    def test_indexdocument_bare_key_exists_index_missing(self, domain):
        with bucket_setup(["key"]):
            response = get(domain, "/key")
            assert response.status_code == 200
            assert response.text == "key"


    def test_indexdocument_slashed_key_exists_index_missing(self, domain):
        with bucket_setup(["key/"]):
            response = get(domain, "/key/")
            assert response.status_code == 404


    def test_indexdocument_slashed_key_exists_index_exists(self, domain):
        with bucket_setup(["key/", "key/index.html"]):
            response = get(domain, "/key/")
            assert response.status_code == 200
            assert response.text == "key/index.html"


    def test_indexdocument_slashed_key_missing_index_exists(self, domain):
        with bucket_setup(["key/index.html"]):
            response = get(domain, "/key/")
            assert response.status_code == 200
            assert response.text == "key/index.html"

    def test_indexdocument_slashed_key_missing_index_exists_query_string_meaningful(self, domain):
        with bucket_setup(["key/index.html"]):
            response = get(domain, "/key/?acl")
            assert response.status_code == 200
            assert response.text == "key/index.html"

    def test_errordocument(self, domain):
        with bucket_setup(["error.html"]):
            response = get(domain, "/key")
            assert response.status_code == 404
            assert response.text == "error.html"

    def test_websiteredirectlocation_absolute(self, domain):
        with bucket_setup(
            [("key", {"WebsiteRedirectLocation": "https://example.org/example"})]
        ):
            response = get(domain, "/key")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "https://example.org/example"


    def test_websiteredirectlocation_relative(self, domain):
        with bucket_setup([("key", {"WebsiteRedirectLocation": "/example"})]):
            response = get(domain, "/key")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "/example"


    def test_websiteredirectlocation_error(self, domain):
        with bucket_setup([("error.html", {"WebsiteRedirectLocation": "/example"})]):
            response = get(domain, "/key")
            assert response.status_code == 301
            assert response.text == "error.html"
            assert response.headers["location"] == "/example"


    def test_websiteredirectlocation_index(self, domain):
        with bucket_setup([("key/index.html", {"WebsiteRedirectLocation": "/example"})]):
            response = get(domain, "/key/")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "/example"

    def test_querystring_meaningful(self, domain):
        with bucket_setup(["key"]):
            response = get(domain, "/key?acl")
            assert response.status_code == 200
            assert response.text == "key"

    def test_redirectallrequeststo_query_string(self, domain):
        with bucket_setup(["key"], {"RedirectAllRequestsTo": {"HostName": "bells.example.com"}}):
            response = get(domain, "/key?query=string")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://bells.example.com/key?query=string"

    def test_redirectallrequeststo_query_string_meaningful(self, domain):
        with bucket_setup(["key"], {"RedirectAllRequestsTo": {"HostName": "swingset.example.com"}}):
            response = get(domain, "/key?acl")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://swingset.example.com/key?acl"

    def test_redirectallrequeststo_default_protocol(self, domain):
        with bucket_setup(["key"], {"RedirectAllRequestsTo": {"HostName": "tiger.example.com"}}):
            response = get(domain, "/key")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://tiger.example.com/key"


    def test_redirectallrequeststo_https_protocol(self, domain):
        with bucket_setup(
            ["key"],
            {"RedirectAllRequestsTo": {"Protocol": "https", "HostName": "burrito.example.com"}},
        ):
            response = get(domain, "/key")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "https://burrito.example.com/key"

    def test_routingrules_condition_none(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Redirect": {"HostName": "apples.example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/any")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://apples.example.com/any"

    def test_routingrules_multiple_matches(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Redirect": {"HostName": "first.example.com"},
                    },
                    {
                        "Redirect": {"HostName": "second.example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/any")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://first.example.com/any"


    def test_routingrules_multiple_matches_http_code_first(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"HttpErrorCodeReturnedEquals": "404"},
                        "Redirect": {"HostName": "primary.example.com"},
                    },
                    {
                        "Redirect": {"HostName": "secondary.example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/any")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://primary.example.com/key"

    def test_routingrules_condition_prefix_empty(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": ""},
                        "Redirect": {"HostName": "example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/any")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://example.com/any"

    def test_routingrules_condition_prefix_matches_key_exists(self, domain):
        with bucket_setup(
            ["r"],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "r"},
                        "Redirect": {"HostName": "example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/r")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://example.com/r"

    def test_routingrules_condition_prefix_matches_index_exists(self, domain):
        with bucket_setup(
            ["r/index.html"],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "r/"},
                        "Redirect": {"HostName": "example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/r/")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://example.com/r/"


    def test_routingrules_condition_prefix_matches_index_missing(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "r/"},
                        "Redirect": {"HostName": "example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/r/")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://example.com/r/"


    def test_routingrules_condition_prefix_matches(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "r"},
                        "Redirect": {"HostName": "example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/rad")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://example.com/rad"


    def test_routingrules_condition_prefix_no_match(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "r"},
                        "Redirect": {"HostName": "example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/bad")
            assert response.status_code == 404


    def test_routingrules_redirectallrequeststo(self, domain):
        with pytest.raises(
            botocore.exceptions.ClientError,
            match=r"RedirectAllRequestsTo cannot be provided in conjunction with other Routing Rules",
        ):
            with bucket_setup(
                [],
                {
                    "RedirectAllRequestsTo": {
                        "Protocol": "https",
                        "HostName": "example.net",
                    },
                    "RoutingRules": [
                        {
                            "Condition": {"KeyPrefixEquals": ""},
                            "Redirect": {"HostName": "example.com"},
                        }
                    ],
                },
            ):
                pass


    def test_routingrules_condition_status_match(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"HttpErrorCodeReturnedEquals": "404"},
                        "Redirect": {"HostName": "glitter.example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/bad")
            assert response.status_code == 301
            assert response.text == ""
            assert response.headers["location"] == "http://glitter.example.com/bad"


    def test_routingrules_condition_status_no_match(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"HttpErrorCodeReturnedEquals": "403"},
                        "Redirect": {"HostName": "glitter.example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/bad")
            assert response.status_code == 404

    def test_routingrules_condition_prefix_and_status_match(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "r", "HttpErrorCodeReturnedEquals": "404"},
                        "Redirect": {"HostName": "aerial.example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/rad")
            assert response.status_code == 301
            assert response.headers["location"] == "http://aerial.example.com/rad"

    def test_routingrules_condition_prefix_and_status_partial_match(self, domain):
        with bucket_setup(
            [],
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "r", "HttpErrorCodeReturnedEquals": "404"},
                        "Redirect": {"HostName": "fascinate.example.com"},
                    }
                ],
            },
        ):
            response = get(domain, "/bad")
            assert response.status_code == 404
