import argparse
from .template import create_template


def get_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--minify", action="store_true", default=False)
    return parser.parse_args(argv)


def main(argv=None):
    args = get_args(argv)
    json_kwargs = {"sort_keys": True}
    if args.minify:
        json_kwargs.update({"indent": None, "separators": (",", ":")})
    print(create_template().to_json(**json_kwargs))
