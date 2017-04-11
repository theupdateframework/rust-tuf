#!/usr/bin/env python3

import binascii
import canonicaljson
import ed25519
import hashlib
import json
import os

from argparse import ArgumentParser
from os import path


def main(output_dir, root, targets, timestamp, snapshot):
    if not path.exists(output_dir):
        raise Exception('Ouput dir does not exist: {}'.format(output_dir))

    os.makedirs(path.join(output_dir, 'keys'), exist_ok=True)
    os.makedirs(path.join(output_dir, 'meta'), exist_ok=True)

    (root_priv, root_pub) = get_key(output_dir, 'root', root)
    (targets_priv, targets_pub) = get_key(output_dir, 'targets', targets)
    (timestamp_priv, timestamp_pub) = get_key(output_dir, 'timestamp', timestamp)
    (snapshot_priv, snapshot_pub) = get_key(output_dir, 'snapshot', snapshot)

    root_meta = make_root(root, root_priv, root_pub,
                          targets, targets_pub,
                          timestamp, timestamp_pub,
                          snapshot, snapshot_pub,
                          )

    targets_meta = make_targets(targets, targets_priv, targets_pub)

    write_meta(output_dir, 'root', root_meta)
    write_meta(output_dir, 'targets', targets_meta)
    #write_meta(output_dir, 'timestamp', timestamp_meta)
    #write_meta(output_dir, 'snapshot', snapshot_meta)


def get_key(output_dir, role, key_type):
    if key_type == 'ed25519':
        try:
            with open(path.join(output_dir, 'keys', '{}.priv'.format(role)), 'r') as f:
                priv = f.read()

            with open(path.join(output_dir, 'keys', '{}.pub'.format(role)), 'r') as f:
                pub = f.read()
        except IOError:
            priv, pub = ed25519.create_keypair()

            priv = binascii.hexlify(priv.to_bytes()).decode('utf-8')
            pub = binascii.hexlify(pub.to_bytes()).decode('utf-8')

            with open(path.join(output_dir, 'keys', '{}.priv'.format(role)), 'w') as f:
                f.write(priv)

            with open(path.join(output_dir, 'keys', '{}.pub'.format(role)), 'w') as f:
                f.write(pub)

    else:
        raise Exception('unknown key type: {}'.format(key_type))


    return (priv, pub)


def write_meta(output_dir, role, meta):
    if not isinstance(meta, bytes):
        raise Exception('meta needs to be bytes')

    with open(path.join(output_dir, 'meta', '{}.json'.format(role)), 'wb') as f:
        f.write(meta)


def make_root(root, root_priv, root_pub,
              targets, targets_pub,
              timestamp, timestamp_pub,
              snapshot, snapshot_pub):

    root_id = key_id(root_pub)
    targets_id = key_id(targets_pub)
    timestamp_id = key_id(timestamp_pub)
    snapshot_id = key_id(snapshot_pub)

    signed = {
            '_type': 'Root',
            'consistent_snapshot': False,
            'expires': '2038-01-19T03:14:06Z',
            'version': 1,
            'keys': {
                root_id: {
                    'keytype': root,
                    'keyval': {
                        'public': root_pub,
                    }
                },
                targets_id: {
                    'keytype': targets,
                    'keyval': {
                        'public': targets_pub,
                    }
                },
                timestamp_id: {
                    'keytype': timestamp,
                    'keyval': {
                        'public': timestamp_pub,
                    }
                },
                snapshot_id: {
                    'keytype': snapshot,
                    'keyval': {
                        'public': snapshot_pub,
                    }
                },
            },
            'roles': {
                'root': {
                    'keyids': [
                        root_id,
                    ],
                    'threshold': 1,
                },
                'targets': {
                    'keyids': [
                        targets_id,
                    ],
                    'threshold': 1,
                },
                'timestamp': {
                    'keyids': [
                        timestamp_id,
                    ],
                    'threshold': 1,
                },
                'snapshot': {
                    'keyids': [
                        snapshot_id,
                    ],
                    'threshold': 1,
                },
            }
        }

    meta = {'signatures': sign(root, root_priv, root_pub, signed), 'signed': signed }
    return canonicaljson.encode_canonical_json(meta)


def make_targets(targets, targets_priv, targets_pub):
    signed = {
        '_type': 'Targets',
        'expires': '2038-01-19T03:14:06Z',
        'version': 1,
        'targets': {
            'hack-eryone.sh': {
                'length': 1337,
                'hashes': {
                    'sha256': '19ad3616216eea07d6f1adb48a774dd61c822a5ae800ef43b65766372ee4869b',
                }
            }
        }
    }

    meta = {'signatures': sign(targets, targets_priv, targets_pub, signed), 'signed': signed }
    return canonicaljson.encode_canonical_json(meta)


def key_id(pub):
    h = hashlib.sha256()
    h.update(pub.encode('utf-8'))  # TODO pretty sure this is wrong according to the spec
    return h.hexdigest()


def sign(method, priv, pub, signed):
    c_json = canonicaljson.encode_canonical_json(signed)

    if method == 'ed25519':
        priv = ed25519.SigningKey(binascii.unhexlify(priv))
        sig = priv.sign(c_json, encoding='hex')
    else:
        raise Exception('unknown sig method: {}'.format(key_type))

    return [{
        'keyid': key_id(pub),
        'method': method,
        'sig': sig.decode('utf-8'),
    }]


if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__), description='makes TUF repos')
    key_choices = ['ed25519']

    parser.add_argument('-o', '--output', help='output dir', default='.')
    parser.add_argument('--root', help='root key type', choices=key_choices, default='ed25519')
    parser.add_argument('--targets', help='targets key type', choices=key_choices, default='ed25519')
    parser.add_argument('--timestamp', help='timestamp key type', choices=key_choices, default='ed25519')
    parser.add_argument('--snapshot', help='snapshot key type', choices=key_choices, default='ed25519')

    args = parser.parse_args()
    main(args.output, args.root, args.targets, args.timestamp, args.snapshot)
