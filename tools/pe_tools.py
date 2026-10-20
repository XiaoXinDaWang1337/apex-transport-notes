#!/usr/bin/env python3
"""PE import / ordinal / cross-reference toolkit (stdlib only).

Why this exists: ws2_32.lib imports BSD socket functions BY ORDINAL, so any
audit that only reads import *names* will report "no send/sendto" on a program
that obviously sends packets. This tool resolves ordinals back to names against
the real system DLL.

Subcommands
    imports   <pe> [--dll NAME]        import table + delay imports + ordinal names
    iatxrefs  <pe> [--dll NAME]        who actually calls each imported function
    pattern   <pe> "48 8B ?? E8"       byte signature scan (?? wildcard)
    strings   <pe> [--min 6] [kw ...]  printable string scan with file offsets

Examples
    pe_tools.py imports r5apex_dx12.exe --dll ws2_32.dll
    pe_tools.py iatxrefs r5apex_dx12.exe --dll ws2_32.dll
    pe_tools.py pattern game.exe "48 89 5C 24 ?? 55 56 57"
"""
import argparse
import re
import struct
import sys


class PE:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.buf = f.read()
        b = self.buf
        if b[:2] != b'MZ':
            raise SystemExit('not a PE: %s' % path)
        self.pe_off = struct.unpack_from('<I', b, 0x3C)[0]
        if b[self.pe_off:self.pe_off + 4] != b'PE\0\0':
            raise SystemExit('not a PE')
        coff = self.pe_off + 4
        (self.machine, self.nsec, self.time_date, _, _,
         self.opt_size, self.chars) = struct.unpack_from('<HHIIIHH', b, coff)
        opt = coff + 20
        self.magic = struct.unpack_from('<H', b, opt)[0]
        self.pe32plus = self.magic == 0x20B
        self.image_base = struct.unpack_from('<Q' if self.pe32plus else '<I', b, opt + 24)[0]
        dd = opt + (112 if self.pe32plus else 96)
        self.dirs = [struct.unpack_from('<II', b, dd + i * 8) for i in range(16)]
        sec = opt + self.opt_size
        self.sections = []
        for i in range(self.nsec):
            o = sec + i * 40
            name = b[o:o + 8].rstrip(b'\0').decode('latin1')
            vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', b, o + 8)
            self.sections.append((name, vaddr, vsize, rptr, rsize))

    def rva_to_off(self, rva):
        for _, vaddr, vsize, rptr, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                d = rva - vaddr
                return rptr + d if d < rsize else None
        return None

    def cstr(self, rva):
        off = self.rva_to_off(rva)
        if off is None:
            return None
        end = self.buf.find(b'\0', off)
        return self.buf[off:end].decode('latin1', 'replace')

    def _thunks(self, rva):
        out = []
        off = self.rva_to_off(rva)
        if off is None:
            return out
        step = 8 if self.pe32plus else 4
        fmt = '<Q' if self.pe32plus else '<I'
        hi = 1 << (63 if self.pe32plus else 31)
        while True:
            v = struct.unpack_from(fmt, self.buf, off)[0]
            if v == 0:
                break
            if v & hi:
                out.append(('ord', v & 0xFFFF))
            else:
                out.append(('name', self.cstr((v & 0x7FFFFFFF) + 2)))
            off += step
        return out

    def imports(self):
        rva, _ = self.dirs[1]
        res = {}
        if not rva:
            return res
        off = self.rva_to_off(rva)
        i = 0
        while off is not None:
            d = self.buf[off + i * 20: off + i * 20 + 20]
            if len(d) < 20:
                break
            ilt, _, _, name_rva, iat = struct.unpack('<IIIII', d)
            if name_rva == 0:
                break
            dll = self.cstr(name_rva) or '?'
            res[dll] = {'iat': iat, 'entries': self._thunks(ilt or iat)}
            i += 1
        return res

    def delay_imports(self):
        rva, _ = self.dirs[13]
        res = {}
        if not rva:
            return res
        off = self.rva_to_off(rva)
        i = 0
        while off is not None:
            d = self.buf[off + i * 32: off + i * 32 + 32]
            if len(d) < 32:
                break
            attrs, name_rva, _, iat, int_rva, _, _, _ = struct.unpack('<IIIIIIII', d)
            if name_rva == 0:
                break
            dll = self.cstr(name_rva) or '?'
            base = 0 if (attrs & 1) else self.image_base
            res[dll] = {'iat': iat, 'entries': self._thunks(int_rva - base if int_rva else 0)}
            i += 1
        return res

    def text(self):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            if name == '.text':
                return vaddr, self.buf[rptr:rptr + rsize]
        raise SystemExit('no .text')


def export_ordinals(dll_path):
    """ordinal -> name for a system DLL."""
    pe = PE(dll_path)
    rva, _ = pe.dirs[0]
    if not rva:
        return {}
    off = pe.rva_to_off(rva)
    base = struct.unpack_from('<I', pe.buf, off + 16)[0]
    nfunc = struct.unpack_from('<I', pe.buf, off + 20)[0]
    nname = struct.unpack_from('<I', pe.buf, off + 24)[0]
    aof = pe.rva_to_off(struct.unpack_from('<I', pe.buf, off + 28)[0])
    aon = pe.rva_to_off(struct.unpack_from('<I', pe.buf, off + 32)[0])
    aoo = pe.rva_to_off(struct.unpack_from('<I', pe.buf, off + 36)[0])
    res = {}
    for i in range(nfunc):
        if struct.unpack_from('<I', pe.buf, aof + i * 4)[0]:
            res[base + i] = None
    for i in range(nname):
        nrva = struct.unpack_from('<I', pe.buf, aon + i * 4)[0]
        idx = struct.unpack_from('<H', pe.buf, aoo + i * 2)[0]
        res[base + idx] = pe.cstr(nrva)
    return res


def cmd_imports(args):
    pe = PE(args.pe)
    imps = pe.imports()
    delay = pe.delay_imports()
    print('file      : %s' % args.pe)
    print('machine   : 0x%x  %s' % (pe.machine, 'PE32+' if pe.pe32plus else 'PE32'))
    print('imports   : %d DLLs / %d functions'
          % (len(imps), sum(len(v['entries']) for v in imps.values())))
    print('delay-load: %d DLLs / %d functions'
          % (len(delay), sum(len(v['entries']) for v in delay.values())))

    cache = {}
    for dll, info in sorted(imps.items(), key=lambda kv: -len(kv[1]['entries'])):
        if args.dll and args.dll.lower() not in dll.lower():
            continue
        ords = [v for k, v in info['entries'] if k == 'ord']
        names = [v for k, v in info['entries'] if k == 'name']
        print('\n%s  (%d by name, %d by ordinal)' % (dll, len(names), len(ords)))
        for n in names:
            print('    name  %s' % n)
        if ords:
            sysdll = r'C:\Windows\System32\%s' % dll
            try:
                if dll not in cache:
                    cache[dll] = export_ordinals(sysdll)
                emap = cache[dll]
            except Exception:
                emap = {}
            for o in sorted(ords):
                print('    ord   %-5d -> %s' % (o, emap.get(o, '<unresolved>')))


def cmd_iatxrefs(args):
    pe = PE(args.pe)
    imps = pe.imports()
    targets = {}
    for dll, info in imps.items():
        if args.dll and args.dll.lower() not in dll.lower():
            continue
        step = 8 if pe.pe32plus else 4
        for i, (kind, val) in enumerate(info['entries']):
            targets[pe.image_base + info['iat'] + i * step] = val
    if not targets:
        raise SystemExit('no imports matched')
    vaddr, blob = pe.text()
    hits = {}
    for i in range(len(blob) - 6):
        if blob[i] != 0xFF or blob[i + 1] not in (0x15, 0x25):
            continue
        disp = struct.unpack_from('<i', blob, i + 2)[0]
        va = pe.image_base + vaddr + i
        if (va + 6 + disp) in targets:
            hits.setdefault(targets[va + 6 + disp], []).append(va)
    rows = sorted(hits.items(), key=lambda kv: -len(kv[1]))
    for val, sites in rows:
        print('%-28s %3d call site(s)  first: 0x%x' % (val, len(sites), sites[0]))
    unused = [v for k, v in targets.items() if v not in hits]
    print('\nnever referenced: %d' % len(unused))


def cmd_pattern(args):
    parts = args.signature.split()
    rx = b''.join(b'.' if p == '??' else re.escape(bytes([int(p, 16)])) for p in parts)
    pe = PE(args.pe)
    vaddr, blob = pe.text()
    hits = [pe.image_base + vaddr + m.start() for m in re.finditer(rx, blob, re.DOTALL)]
    print('hits: %d' % len(hits))
    for h in hits[:20]:
        print('  0x%x' % h)


def cmd_strings(args):
    pe = PE(args.pe)
    rx = re.compile(rb'[\x20-\x7e]{%d,}' % args.min)
    seen = 0
    for m in rx.finditer(pe.buf):
        s = m.group().decode('latin1')
        if args.kw and not any(k.lower() in s.lower() for k in args.kw):
            continue
        print('0x%08x  %s' % (m.start(), s[:160]))
        seen += 1
        if seen >= args.limit:
            break


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('imports'); p.add_argument('pe'); p.add_argument('--dll')
    p.set_defaults(func=cmd_imports)

    p = sub.add_parser('iatxrefs'); p.add_argument('pe'); p.add_argument('--dll', required=True)
    p.set_defaults(func=cmd_iatxrefs)

    p = sub.add_parser('pattern'); p.add_argument('pe'); p.add_argument('signature')
    p.set_defaults(func=cmd_pattern)

    p = sub.add_parser('strings')
    p.add_argument('pe'); p.add_argument('--min', type=int, default=6)
    p.add_argument('--limit', type=int, default=200)
    p.add_argument('kw', nargs='*')
    p.set_defaults(func=cmd_strings)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
