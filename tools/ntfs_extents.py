#!/usr/bin/env python3
"""Read kernel-locked files through the raw NTFS volume.

pagefile.sys / hiberfil.sys / MEMORY.DMP cannot be opened while the system runs,
but NTFS keeps every file's physical cluster list in its $DATA attribute, and
\\\\.\\C: is readable by an administrator. So: parse the MFT, take the runlist,
read those clusters.

    python ntfs_extents.py info    C
    python ntfs_extents.py extents C pagefile.sys
    python ntfs_extents.py dump    C pagefile.sys out.bin --max-mb 2048
    python ntfs_extents.py find    C page          # substring match on file names

Requires: Administrator. Read-only: nothing is written to the volume.
"""
import argparse
import struct
import sys


class Volume:
    def __init__(self, letter):
        self.f = open('\\\\.\\%s:' % letter, 'rb', buffering=0)
        bs = self.f.read(512)
        self.bytes_per_sector = struct.unpack_from('<H', bs, 0x0B)[0]
        self.sectors_per_cluster = bs[0x0D]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.total_sectors = struct.unpack_from('<Q', bs, 0x28)[0]
        self.mft_lcn = struct.unpack_from('<Q', bs, 0x30)[0]
        rec = struct.unpack_from('<b', bs, 0x40)[0]
        self.record_size = rec * self.cluster_size if rec > 0 else 1 << (-rec)

    def read_clusters(self, lcn, count):
        """Read count clusters in bounded chunks (single large reads fail)."""
        self.f.seek(lcn * self.cluster_size)
        remaining = count * self.cluster_size
        out = []
        while remaining > 0:
            n = min(32 * 1024 * 1024, remaining)
            b = self.f.read(n)
            if not b:
                break
            out.append(b)
            remaining -= len(b)
        return b''.join(out)


def runlist(data):
    """[(lcn, length), ...] — NTFS data runs."""
    runs, i, cur = [], 0, 0
    while i < len(data) and data[i]:
        hdr = data[i]
        len_sz, off_sz = hdr & 0x0F, (hdr >> 4) & 0x0F
        i += 1
        ln = int.from_bytes(data[i:i + len_sz], 'little')
        i += len_sz
        if off_sz == 0:
            continue
        delta = int.from_bytes(data[i:i + off_sz], 'little', signed=True)
        i += off_sz
        cur += delta
        runs.append((cur, ln))
    return runs


def attrs(rec):
    if rec[:4] != b'FILE':
        return
    off = struct.unpack_from('<H', rec, 0x14)[0]
    while off + 8 <= len(rec):
        atype, alen = struct.unpack_from('<II', rec, off)
        if atype == 0xFFFFFFFF:
            break
        non_res = rec[off + 8]
        name_len = rec[off + 9]
        name_off = struct.unpack_from('<H', rec, off + 0x0A)[0]
        name = (rec[off + name_off:off + name_off + name_len * 2]
                .decode('utf-16le', 'ignore') if name_len else '')
        if non_res:
            roff = struct.unpack_from('<H', rec, off + 0x20)[0]
            real = struct.unpack_from('<Q', rec, off + 0x30)[0]
            yield atype, True, name, rec[off + roff:off + alen], real
        else:
            vlen = struct.unpack_from('<I', rec, off + 0x10)[0]
            voff = struct.unpack_from('<H', rec, off + 0x14)[0]
            yield atype, False, name, rec[off + voff:off + voff + vlen], vlen
        off += alen


def load_mft(v):
    rec0 = v.read_clusters(v.mft_lcn, 1)[:v.record_size]
    for atype, non_res, name, val, real in attrs(rec0):
        if atype == 0x80 and not name:
            return runlist(val)
    raise SystemExit('cannot locate $MFT runlist')


def iter_records(v, runs):
    buf = b''
    for lcn, ln in runs:
        buf += v.read_clusters(lcn, ln)
    n = len(buf) // v.record_size
    for i in range(n):
        yield buf[i * v.record_size:(i + 1) * v.record_size]


def find(v, runs, target, substring=False):
    tl = target.lower()
    for rec in iter_records(v, runs):
        if rec[:4] != b'FILE':
            continue
        name = None
        data = None
        size = 0
        for atype, non_res, aname, val, real in attrs(rec):
            if atype == 0x30 and not aname:
                try:
                    n = val[0x40]
                    name = val[0x42:0x42 + n * 2].decode('utf-16le', 'ignore')
                except Exception:
                    pass
            elif atype == 0x80 and not aname and non_res:
                data = runlist(val)
                size = real
        if not name:
            continue
        hit = (tl in name.lower()) if substring else (name.lower() == tl)
        if hit:
            yield name, data, size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['info', 'extents', 'dump', 'find'])
    ap.add_argument('letter')
    ap.add_argument('target', nargs='?')
    ap.add_argument('out', nargs='?')
    ap.add_argument('--max-mb', type=int, default=2048)
    args = ap.parse_args()

    v = Volume(args.letter)
    print('cluster=%d  sector=%d  mft_lcn=%d  record=%d'
          % (v.cluster_size, v.bytes_per_sector, v.mft_lcn, v.record_size))
    runs = load_mft(v)
    print('$MFT runs=%d clusters=%d' % (len(runs), sum(l for _, l in runs)))
    if args.mode == 'info':
        return

    found = list(find(v, runs, args.target, substring=(args.mode == 'find')))
    if not found:
        print('not found:', args.target)
        return
    for name, data, size in found[:20]:
        print('%-24s %.1f MB  runs=%d' % (name, size / 1048576, len(data or [])))
        if args.mode == 'extents':
            for lcn, ln in (data or [])[:20]:
                print('    lcn=%-12d clusters=%d' % (lcn, ln))

    if args.mode == 'dump':
        name, data, size = found[0]
        if not args.out:
            raise SystemExit('dump needs an output path')
        written = 0
        limit = args.max_mb * 1048576
        with open(args.out, 'wb') as w:
            for lcn, ln in data:
                if written >= limit:
                    break
                take = min(ln * v.cluster_size, size - written, limit - written)
                if take <= 0:
                    break
                w.write(v.read_clusters(lcn, (take + v.cluster_size - 1) // v.cluster_size)[:take])
                written += take
        print('wrote %s : %.1f MB' % (args.out, written / 1048576))


if __name__ == '__main__':
    main()
