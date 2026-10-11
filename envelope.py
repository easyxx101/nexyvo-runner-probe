"""Versioned hybrid encryption; only public recipient material belongs on a runner."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'EVSEAL01'
LIMIT = 512 * 1024 * 1024
LABEL = b'EVSEAL01 file key'
ALGORITHM = 'RSA3072-OAEP-SHA256+AES256-GCM'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def context(value):
    if (not isinstance(value, dict) or set(value) != {'campaign', 'run_id', 'run_attempt', 'controller_sha'}
            or not re.fullmatch(r'[0-9a-f]{32}', value.get('campaign', ''))
            or not re.fullmatch(r'[1-9][0-9]{0,19}', value.get('run_id', ''))
            or value.get('run_attempt') != '1'
            or not re.fullmatch(r'[0-9a-f]{40}', value.get('controller_sha', ''))):
        raise ValueError('Invalid evidence context')
    return value


def public_key(pem):
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072:
        raise ValueError('RSA3072 recipient required')
    return key


def fingerprint(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=LABEL)


def seal(data, recipient, binding):
    if len(data) > LIMIT:
        raise ValueError('Evidence exceeds bound')
    key = public_key(recipient)
    file_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    header = canonical(dict(algorithm=ALGORITHM, context=context(binding), plaintext_size=len(data),
        recipient_sha256=fingerprint(key), nonce=base64.b64encode(nonce).decode('ascii'),
        wrapped_key=base64.b64encode(key.encrypt(file_key, oaep())).decode('ascii')))
    aad = MAGIC + struct.pack('>I', len(header)) + header
    return aad + AESGCM(file_key).encrypt(nonce, data, aad)


def unseal(data, private_pem, expected_context):
    if len(data) > LIMIT+8192 or len(data) < 28 or data[:8] != MAGIC:
        raise ValueError('Invalid envelope')
    size = struct.unpack('>I', data[8:12])[0]
    if not 1 <= size <= 4096 or len(data) < 12+size+16:
        raise ValueError('Invalid envelope header')
    raw = data[12:12+size]
    header = json.loads(raw)
    if (canonical(header) != raw or set(header) != {'algorithm', 'context', 'plaintext_size',
            'recipient_sha256', 'nonce', 'wrapped_key'} or header['algorithm'] != ALGORITHM
            or context(header['context']) != context(expected_context)
            or type(header['plaintext_size']) is not int or not 0 <= header['plaintext_size'] <= LIMIT
            or len(data)-12-size != header['plaintext_size']+16):
        raise ValueError('Evidence binding or size mismatch')
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072:
        raise ValueError('RSA3072 private key required')
    if fingerprint(key.public_key()) != header['recipient_sha256']:
        raise ValueError('Recipient mismatch')
    nonce = base64.b64decode(header['nonce'], validate=True)
    wrapped = base64.b64decode(header['wrapped_key'], validate=True)
    if len(nonce) != 12 or len(wrapped) != 384:
        raise ValueError('Invalid encryption parameters')
    file_key = key.decrypt(wrapped, oaep())
    if len(file_key) != 32:
        raise ValueError('Invalid file key')
    # No plaintext is returned or written before the complete 128-bit tag validates.
    return AESGCM(file_key).decrypt(nonce, data[12+size:], data[:12+size])


def generate(private_path, public_path):
    if private_path.exists() or public_path.exists():
        raise ValueError('Refused key replacement')
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with public_path.open('xb') as stream:
        stream.write(key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    return fingerprint(key.public_key())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['keygen', 'seal', 'unseal'])
    parser.add_argument('--private', type=Path)
    parser.add_argument('--public', type=Path)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--context', type=Path)
    args = parser.parse_args()
    if args.mode == 'keygen':
        print(json.dumps({'recipient_sha256': generate(args.private, args.public)}))
    else:
        binding = json.loads(args.context.read_text(encoding='utf-8'))
        data = args.input.read_bytes()
        result = seal(data, args.public.read_bytes(), binding) if args.mode == 'seal' else unseal(
            data, args.private.read_bytes(), binding)
        with args.output.open('xb') as stream:
            stream.write(result)
        print(json.dumps({'bytes': len(result), 'sha256': hashlib.sha256(result).hexdigest()}))


if __name__ == '__main__':
    main()
