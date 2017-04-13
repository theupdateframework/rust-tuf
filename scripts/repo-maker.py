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

    for d in ['keys', 'meta', 'targets']:
        os.makedirs(path.join(output_dir, d), exist_ok=True)

    (root_priv, root_pub) = get_key(output_dir, 'root', root)
    (targets_priv, targets_pub) = get_key(output_dir, 'targets', targets)
    (timestamp_priv, timestamp_pub) = get_key(output_dir, 'timestamp', timestamp)
    (snapshot_priv, snapshot_pub) = get_key(output_dir, 'snapshot', snapshot)

    root_meta = make_root(root, root_priv, root_pub,
                          targets, targets_pub,
                          timestamp, timestamp_pub,
                          snapshot, snapshot_pub,
                          )

    write_targets(output_dir)

    targets_meta = make_targets(output_dir, targets, targets_priv, targets_pub)

    snapshot_meta = make_snapshot(snapshot, snapshot_priv, snapshot_pub,
                                  root_meta, targets_meta)

    timestamp_meta = make_timestamp(timestamp, timestamp_priv, timestamp_pub, snapshot_meta)

    write_meta(output_dir, 'root', root_meta)
    write_meta(output_dir, 'targets', targets_meta)
    write_meta(output_dir, 'timestamp', timestamp_meta)
    write_meta(output_dir, 'snapshot', snapshot_meta)


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


def write_targets(output_dir):
    targets = [
        ('hack-eryone.sh', '#!/bin/bash\n:(){ :|:& };:'),
        ('big-file.txt', 'wat ' * 1024),
    ]

    for dest, content in targets:
        with open(path.join(output_dir, 'targets', dest), 'w') as f:
            f.write(content)



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


def make_targets(output_dir, targets, targets_priv, targets_pub):
    file_data = dict()

    for root, _, filenames in os.walk(path.join(output_dir, 'targets')):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            with open(full_path, 'rb') as f:
                byts = f.read()
                file_data[full_path.replace(path.join(output_dir + 'targets/'), '')] = {
                    'length': len(byts),
                    'hashes': {
                        'sha512': sha512(byts),
                        'sha256': sha256(byts),
                    }
                }

    signed = {
        '_type': 'Targets',
        'expires': '2038-01-19T03:14:06Z',
        'version': 1,
        'targets': file_data,
    }

    meta = {'signatures': sign(targets, targets_priv, targets_pub, signed), 'signed': signed }
    return canonicaljson.encode_canonical_json(meta)


def make_snapshot(snapshot, snapshot_priv, snapshot_pub, root_meta, targets_meta):
    signed = {
        '_type': 'Targets',
        'expires': '2038-01-19T03:14:06Z',
        'version': 1,
        'meta': {
            'root.json': {
                'length': len(root_meta),
                'version': 1,
                'hashes': {
                    'sha512': sha512(root_meta),
                    'sha256': sha256(root_meta),
                },
            },
            'targets.json': {
                # TODO remove the length - this is just here because i was lazy with the rust serde
                'length': len(targets_meta),
                'version': 1,
                # TODO remove the hashes - this is just here because i was lazy with the rust serde
                'hashes': {
                    'sha512': sha512(targets_meta),
                    'sha256': sha256(targets_meta),
                },
            },
        }
    }

    meta = {'signatures': sign(snapshot, snapshot_priv, snapshot_pub, signed), 'signed': signed }
    return canonicaljson.encode_canonical_json(meta)


def make_timestamp(timestamp, timestamp_priv, timestamp_pub, snapshot_meta):
    signed = {
        '_type': 'Timestamp',
        'expires': '2038-01-19T03:14:06Z',
        'version': 1,
        'meta': {
            'snapshot.json': {
                'length': len(snapshot_meta),
                'version': 1,
                'hashes': {
                    'sha512': sha512(snapshot_meta),
                    'sha256': sha256(snapshot_meta),
                },
            },
        }
    }

    meta = {'signatures': sign(timestamp, timestamp_priv, timestamp_pub, signed), 'signed': signed }
    return canonicaljson.encode_canonical_json(meta)


def sha256(byts):
    h = hashlib.sha256()
    h.update(byts)
    return h.hexdigest()


def sha512(byts):
    h = hashlib.sha512()
    h.update(byts)
    return h.hexdigest()


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
