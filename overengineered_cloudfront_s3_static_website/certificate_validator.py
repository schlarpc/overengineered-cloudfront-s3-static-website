import boto3
import enum
import json
import os


class EnvVars(enum.Enum):
    HOSTED_ZONE_ID = enum.auto()

    @property
    def value(self):
        return os.environ[self.name]


def handler(event, context=None):
    print(json.dumps(event))
