import collections
import datetime
import functools
import gzip
import itertools
import json
import sys
import uuid

import boto3

LOG_BATCH_MAX_ITEMS = 10000
LOG_BATCH_MAX_BYTES = 1_048_576
LOG_EVENT_OVERHEAD = 26


class LogEvent(collections.namedtuple("LogEntry", ["timestamp", "message"])):
    @property
    def encoded_size(self):
        return len(self.message)

    def as_dict(self):
        return dict(
            timestamp=int(self.timestamp.timestamp() * 1000),
            message=self.message.decode("utf-8"),
        )


@functools.lru_cache()
def get_client(service, region_name=None):
    kwargs = {"region_name": region_name} if region_name else {}
    client = boto3.client(service, **kwargs)
    if service == "logs":
        client.meta.events.register("before-sign.logs.PutLogEvents", gzip_request_body)
    return client


def gzip_request_body(request, **_):
    if "Content-Encoding" not in request.headers:
        request.headers.add_header("Content-Encoding", "gzip")
        request.data = gzip.compress(request.body)


def get_s3_stream(key_basename, body):
    def _create_stream():
        for message in body.iter_lines():
            timestamp = datetime.datetime.strptime(
                message.split(b"[", 1)[1].split(b"]")[0].decode("utf-8"),
                "%d/%b/%Y:%H:%M:%S %z",
            )
            yield LogEvent(timestamp=timestamp, message=message)

    stream = _create_stream()
    first_event = []
    for event in stream:
        first_event.append(event)
        bucket_name = event.message.split(b" ")[1].decode("utf-8")
        break
    return bucket_name, key_basename, itertools.chain(first_event, stream)


def get_cloudfront_stream(key_basename, body):
    def _create_stream():
        for line in gzip.GzipFile(fileobj=body):
            message = line.rstrip(b"\r\n")
            if message.startswith(b"#"):
                continue
            timestamp = datetime.datetime.strptime(
                b" ".join(message.split(b"\t")[:2]).decode("utf-8"), "%Y-%m-%d %H:%M:%S"
            )
            yield LogEvent(timestamp=timestamp, message=message)

    distribution_name, log_name = key_basename.rstrip(".gz").split(".", 1)
    return distribution_name, log_name, _create_stream()


def get_event_stream(record):
    service, key_basename = record["s3"]["object"]["key"].split("/", 1)
    try:
        streamer = {"s3": get_s3_stream, "cloudfront": get_cloudfront_stream}[service]
    except KeyError:
        raise ValueError(f"Unknown log prefix {service!r}")
    s3 = get_client("s3", region_name=record["awsRegion"])
    response = s3.get_object(
        Bucket=record["s3"]["bucket"]["name"], Key=record["s3"]["object"]["key"]
    )
    return (service,) + streamer(key_basename, response["Body"])


def write_events_to_log_stream(logs, group_name, stream_name, events):
    kwargs = {}
    batch = []
    batch_size = 0
    for event in sorted(events):
        next_batch_size = batch_size + event.encoded_size + LOG_EVENT_OVERHEAD
        if next_batch_size >= LOG_BATCH_MAX_BYTES or len(batch) >= LOG_BATCH_MAX_ITEMS:
            response = logs.put_log_events(
                logGroupName=group_name,
                logStreamName=stream_name,
                logEvents=batch,
                **kwargs,
            )
            kwargs["sequenceToken"] = response["nextSequenceToken"]
            batch = []
            batch_size = 0
        batch.append(event.as_dict())
        batch_size += event.encoded_size + LOG_EVENT_OVERHEAD
    if batch:
        response = logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=batch,
            **kwargs,
        )


def handler(event, context=None):
    print(json.dumps(event))
    logs = get_client("logs")
    for record in event["Records"]:
        service, resource_name, log_name, stream = get_event_stream(record)
        group_name = f"/aws/{service}/{resource_name}"
        stream_name = f"{log_name}/" + str(uuid.uuid4())
        logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
        write_events_to_log_stream(logs, group_name, stream_name, stream)


if __name__ == "__main__":
    print(handler(json.loads(sys.argv[1])))
