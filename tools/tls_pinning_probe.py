#!/usr/bin/env python3
"""Decide whether a TLS client validates against the OS trust store or a
built-in pinned list.

Method: generate a CA, install it into the OS root store, serve a fully
compliant leaf certificate for the target host from a local sink, redirect the
host to it, and watch whether the handshake completes.

    - handshake completes  -> the client uses the OS store (MITM viable)
    - client aborts        -> validation is enforced elsewhere (pinning)

Requires cryptography:  pip install cryptography

    tls_pinning_probe.py gen  host1 host2
    tls_pinning_probe.py serve 443
    tls_pinning_probe.py install   <ca.crt>     # Windows, adds to LocalMachine\\Root
    tls_pinning_probe.py uninstall              # removes certs named like the test CA
"""
import argparse
import datetime
import os
import socket
import ssl
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = os.path.dirname(os.path.abspath(__file__))
CA_CN = 'DSH Test Root CA'


def gen(hosts):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)])
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False,
                                         False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))

    ca_p = os.path.join(OUT, 'test-ca.crt')
    leaf_p = os.path.join(OUT, 'test-leaf.crt')
    key_p = os.path.join(OUT, 'test-leaf.key')
    open(ca_p, 'wb').write(ca.public_bytes(serialization.Encoding.PEM))
    open(leaf_p, 'wb').write(leaf.public_bytes(serialization.Encoding.PEM)
                             + ca.public_bytes(serialization.Encoding.PEM))
    open(key_p, 'wb').write(leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    print('ca   :', ca_p)
    print('leaf :', leaf_p)
    print('key  :', key_p)


def serve(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(OUT, 'test-leaf.crt'), os.path.join(OUT, 'test-leaf.key'))
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.sni_callback = lambda s, name, c: print('[sni ] %r' % name, flush=True)

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(16)
    print('[+] sink on :%d' % port, flush=True)
    while True:
        c, addr = s.accept()
        print('[conn] %s:%d' % addr, flush=True)
        try:
            t = ctx.wrap_socket(c, server_side=True)
            print('[tls ] HANDSHAKE OK %s %s alpn=%s'
                  % (t.version(), t.cipher()[0], t.selected_alpn_protocol()), flush=True)
            d = t.recv(8192)
            print('[data] %d bytes %r' % (len(d), d[:200]), flush=True)
            t.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
            t.close()
        except ssl.SSLError as e:
            print('[tls ] FAIL %s' % e, flush=True)
        except Exception as e:
            print('[err ] %s' % e, flush=True)
        finally:
            try:
                c.close()
            except Exception:
                pass


def install(ca_path):
    ps = ("Import-Certificate -FilePath '%s' -CertStoreLocation Cert:\\LocalMachine\\Root | "
          "Select-Object Subject,Thumbprint | Format-List" % ca_path)
    subprocess.run(['powershell', '-NoProfile', '-Command', ps], check=False)


def uninstall():
    ps = ("Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like '*%s*' } | "
          "ForEach-Object { Remove-Item -LiteralPath $_.PSPath -Force; $_.Thumbprint }" % CA_CN)
    subprocess.run(['powershell', '-NoProfile', '-Command', ps], check=False)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('gen'); p.add_argument('hosts', nargs='+')
    p = sub.add_parser('serve'); p.add_argument('port', type=int, nargs='?', default=443)
    p = sub.add_parser('install'); p.add_argument('ca')
    p = sub.add_parser('uninstall')
    args = ap.parse_args()
    if args.cmd == 'gen':
        gen(args.hosts)
    elif args.cmd == 'serve':
        serve(args.port)
    elif args.cmd == 'install':
        install(args.ca)
    else:
        uninstall()


if __name__ == '__main__':
    main()
