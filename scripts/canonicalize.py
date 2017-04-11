#!/usr/bin/env python3

import canonicaljson
import json
import os

from argparse import ArgumentParser
from os import path


def main(_file):
    with open(_file, 'r') as f:
        jsn = f.read()

    # Yes, decoding as UTF-8 is non-sensical, but it works for the test cases
    print(canonicaljson.encode_canonical_json(json.loads(jsn)).decode('utf-8'))


if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__), description='makes TUF repos')

    parser.add_argument('file', help='file to canonicalize')
    
    args = parser.parse_args()
    main(args.file)
