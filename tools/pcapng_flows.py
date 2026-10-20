#!/usr/bin/env python3
"""pcapng flow summary + TLS SNI extraction (stdlib only).

Answers two questions about a capture without any packet library:
  - which flows exist, how big, in which direction
  - which TLS hosts the client talked to (SNI is cleartext even when the
    request payload is not)

    python pcapng_flows.py capture.pcapng [--json out.json] [--top 30]
"""
import argparse
import json
import struct
from collections import defaultdict


def read_pcapng(path):
    data = open(path, 'rb').read()
    off = 0
    tsresol, linktype, iface = {}, {}, 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from('<II', data, off)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8: off + blen - 4]
        if btype == 1:                                  # IDB
            linktype[iface] = struct.unpack_from('<H', body, 0)[0]
            tsresol[iface] = 1e-6
            o = 8
            while o + 4 <= len(body):
                code, olen = struct.unpack_from('<HH', body, o)
                o += 4
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = body[o]
                    tsresol[iface] = (2.0 ** -(v & 0x7f)) if (v & 0x80) else (10.0 ** -v)
                o += olen + ((4 - olen % 4) % 4)
            iface += 1
        elif btype == 6:                                # EPB
            iid, tshi, tslo, cap, _ = struct.unpack_from('<IIIII', body, 0)
            ts = ((tshi << 32) | tslo) * tsresol.get(iid, 1e-6)
            yield ts, linktype.get(iid, 1), body[20:20 + cap]
        off += blen


def parse_ip(pkt, lt):
    if lt == 1:
        if len(pkt) < 14:
            return None
        et = struct.unpack_from('>H', pkt, 12)[0]
        o = 14
        while et in (0x8100, 0x88a8) and len(pkt) >= o + 4:
            et = struct.unpack_from('>H', pkt, o + 2)[0]
            o += 4
        if et != 0x0800:
            return None
        pkt = pkt[o:]
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0xF) * 4
    total = struct.unpack_from('>H', pkt, 2)[0]
    proto = pkt[9]
    src = '.'.join(str(b) for b in pkt[12:16])
    dst = '.'.join(str(b) for b in pkt[16:20])
    end = min(total, len(pkt)) if total else len(pkt)
    if proto == 6 and end >= ihl + 20:
        sp, dp = struct.unpack_from('>HH', pkt, ihl)
        doff = (pkt[ihl + 12] >> 4) * 4
        return 'tcp', src, dst, sp, dp, pkt[ihl + doff:end]
    if proto == 17 and end >= ihl + 8:
        sp, dp, ul = struct.unpack_from('>HHH', pkt, ihl)
        return 'udp', src, dst, sp, dp, pkt[ihl + 8:min(ihl + ul, end)]
    return None


def sni_from_client_hello(payload):
    if len(payload) < 43 or payload[0] != 0x16:
        return None
    try:
        p = 5 + 4 + 2 + 32
        p += 1 + payload[p]
        p += 2 + struct.unpack_from('>H', payload, p)[0]
        p += 1 + payload[p]
        total = struct.unpack_from('>H', payload, p)[0]
        p += 2
        end = min(p + total, len(payload))
        while p + 4 <= end:
            et, el = struct.unpack_from('>HH', payload, p)
            p += 4
            if et == 0:
                q = p + 2
                while q + 3 <= p + el:
                    ntype = payload[q]
                    nlen = struct.unpack_from('>H', payload, q + 1)[0]
                    if ntype == 0:
                        return payload[q + 3:q + 3 + nlen].decode('latin1')
                    q += 3 + nlen
                return None
            p += el
    except Exception:
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcapng')
    ap.add_argument('--json')
    ap.add_argument('--top', type=int, default=20)
    args = ap.parse_args()

    flows = defaultdict(lambda: {'pkts': 0, 'bytes': 0, 'first': None, 'last': None, 'sni': None})
    for ts, lt, pkt in read_pcapng(args.pcapng):
        r = parse_ip(pkt, lt)
        if not r:
            continue
        proto, src, dst, sp, dp, payload = r
        f = flows[(proto, src, sp, dst, dp)]
        f['pkts'] += 1
        f['bytes'] += len(payload)
        f['first'] = f['first'] or ts
        f['last'] = ts
        if proto == 'tcp' and dp == 443 and payload[:1] == b'\x16':
            s = sni_from_client_hello(payload)
            if s:
                f['sni'] = s

    rows = sorted(flows.items(), key=lambda kv: -kv[1]['pkts'])[:args.top]
    print('%-4s %-24s -> %-24s %8s %10s  %s' % ('proto', 'src', 'dst', 'pkts', 'bytes', 'sni'))
    for (proto, src, sp, dst, dp), f in rows:
        print('%-4s %-24s -> %-24s %8d %10d  %s'
              % (proto, '%s:%d' % (src, sp), '%s:%d' % (dst, dp),
                 f['pkts'], f['bytes'], f['sni'] or ''))

    if args.json:
        out = [{'proto': k[0], 'src': '%s:%d' % (k[1], k[2]), 'dst': '%s:%d' % (k[3], k[4]), **v}
               for k, v in flows.items()]
        json.dump(out, open(args.json, 'w'), indent=1)
        print('\nwrote', args.json)


if __name__ == '__main__':
    main()
