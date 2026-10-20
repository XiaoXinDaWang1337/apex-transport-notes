#!/usr/bin/env python3
"""AEAD tag as a key oracle — and a scanner for candidate keys inside blobs.

The point: an AEAD authentication tag is a 128-bit predicate. A wrong key cannot
pass it by accident, so candidate keys need no statistics, no threshold, no
human judgement — one decryption decides.

Requires pycryptodome:  pip install pycryptodome

    # 1. does this key decrypt this packet?
    aead_oracle.py try <key> --nonce <hex> --ct <hex> --tag <hex>

    # 2. find the key inside a memory image / dump / pagefile copy
    aead_oracle.py scan <blob> --nonce <hex> --ct <hex> --tag <hex> [--brute] [--max-mb N]

    # 3. prove the tool works before trusting a negative result
    aead_oracle.py selftest
"""
import argparse
import base64
import binascii
import os
import re
import sys
import tempfile

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
except ImportError:
    raise SystemExit('pip install pycryptodome')

B64_24 = re.compile(rb'[A-Za-z0-9+/]{22}==')
CHUNK = 16 * 1024 * 1024
OVERLAP = 64


def coerce_key(text):
    text = text.strip()
    try:
        raw = binascii.unhexlify(text)
        if len(raw) in (16, 32):
            return raw
    except Exception:
        pass
    try:
        raw = base64.b64decode(text, validate=True)
        if len(raw) in (16, 32):
            return raw
    except Exception:
        pass
    if len(text) in (16, 32):
        return text.encode()
    raise SystemExit('key must be 16/32 bytes as hex, base64 or raw ascii')


def verify(key, nonce, ct, tag):
    if len(key) == 16:
        try:
            AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
            return 'AES-128-GCM'
        except Exception:
            pass
    if len(key) == 32:
        try:
            ChaCha20_Poly1305.new(key=key, nonce=nonce).decrypt_and_verify(ct, tag)
            return 'ChaCha20-Poly1305'
        except Exception:
            pass
    if len(key) == 16:
        try:
            ChaCha20_Poly1305.new(key=key, nonce=nonce).decrypt_and_verify(ct, tag)
            return 'ChaCha20-Poly1305 (16B key)'
        except Exception:
            pass
    return None


def cmd_try(args):
    key = coerce_key(args.key)
    n, c, t = (bytes.fromhex(x) for x in (args.nonce, args.ct, args.tag))
    algo = verify(key, n, c, t)
    print('key :', key.hex())
    print('tag : %s' % ('VALID  -> %s' % algo if algo else 'invalid'))
    return 0 if algo else 1


def scan_blob(path, nonce, ct, tag, brute, max_bytes, quiet):
    total = checked = hits = 0
    with open(path, 'rb') as f:
        carry = b''
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            data = carry + buf
            base = total - len(carry)
            total += len(buf)

            for m in B64_24.finditer(data):
                try:
                    key = base64.b64decode(m.group())
                except Exception:
                    continue
                if len(key) not in (16, 32):
                    continue
                checked += 1
                algo = verify(key, nonce, ct, tag)
                if algo:
                    hits += 1
                    print('HIT base64 @0x%x key=%s %s' % (base + m.start(), key.hex(), algo))

            if brute and (max_bytes is None or total <= max_bytes):
                for i in range(max(0, len(data) - 16)):
                    key = data[i:i + 16]
                    checked += 1
                    if verify(key, nonce, ct, tag):
                        hits += 1
                        print('HIT raw @0x%x key=%s' % (base + i, key.hex()))
                        return hits, checked

            carry = data[-OVERLAP:]
            if not quiet:
                print('  %.0f MB, %d candidates' % (total / 1048576, checked), file=sys.stderr)
            if max_bytes and total >= max_bytes:
                break
    return hits, checked


def cmd_scan(args):
    n, c, t = (bytes.fromhex(x) for x in (args.nonce, args.ct, args.tag))
    limit = args.max_mb * 1048576 if args.max_mb else None
    hits, checked = scan_blob(args.blob, n, c, t, args.brute, limit, args.quiet)
    print('result: %d hit(s) / %d candidates' % (hits, checked))
    return 0 if hits else 1


def cmd_selftest(_args):
    """Plant a key and prove the scanner finds it at the exact offsets."""
    key = os.urandom(16)
    nonce = os.urandom(12)
    plain = b'structured plaintext payload' * 8
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(plain)
    blob = bytearray(os.urandom(2 * 1024 * 1024))
    b64 = base64.b64encode(key)
    ob, orw = 1000000, 1500000
    blob[ob:ob + len(b64)] = b64
    blob[orw:orw + 16] = key
    fd, path = tempfile.mkstemp()
    os.close(fd)
    open(path, 'wb').write(bytes(blob))
    print('key=%s  base64@0x%x  raw@0x%x' % (key.hex(), ob, orw))

    h1, c1 = scan_blob(path, nonce, ct, tag, False, None, True)
    h2, c2 = scan_blob(path, nonce, ct, tag, True, None, True)
    os.unlink(path)
    print('base64 pass: hits=%d checked=%d' % (h1, c1))
    print('brute  pass: hits=%d checked=%d' % (h2, c2))
    ok = h1 >= 1 and h2 >= 1
    print('SELFTEST', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('try')
    p.add_argument('key'); p.add_argument('--nonce', required=True)
    p.add_argument('--ct', required=True); p.add_argument('--tag', required=True)
    p.set_defaults(func=cmd_try)

    p = sub.add_parser('scan')
    p.add_argument('blob'); p.add_argument('--nonce', required=True)
    p.add_argument('--ct', required=True); p.add_argument('--tag', required=True)
    p.add_argument('--brute', action='store_true')
    p.add_argument('--max-mb', type=int)
    p.add_argument('--quiet', action='store_true')
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser('selftest')
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
