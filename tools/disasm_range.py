#!/usr/bin/env python3
"""Disassemble a VA range from a PE and annotate rip-relative string references.

Requires capstone:  pip install capstone

    python disasm_range.py <pe> 0x140001000 0x200
    python disasm_range.py <pe> 0x140001000 0x200 --hex

Addresses are virtual addresses (image base included), which is what IDA/Ghidra
show by default.
"""
import argparse
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    raise SystemExit('pip install capstone')

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from pe_tools import PE  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pe')
    ap.add_argument('va', type=lambda s: int(s, 0))
    ap.add_argument('size', type=lambda s: int(s, 0))
    ap.add_argument('--hex', action='store_true', help='print raw bytes too')
    args = ap.parse_args()

    pe = PE(args.pe)
    off = pe.rva_to_off(args.va - pe.image_base)
    if off is None:
        raise SystemExit('address not mapped')

    def cstr(va, n=90):
        o = pe.rva_to_off(va - pe.image_base)
        if o is None:
            return None
        raw = pe.buf[o:pe.buf.find(b'\0', o)]
        if len(raw) < 3:
            return None
        if sum(32 <= c < 127 for c in raw) < len(raw) * 0.75:
            return None
        return raw.decode('latin1')[:n]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    code = pe.buf[off:off + args.size]
    for ins in md.disasm(code, args.va):
        note = ''
        ops = ins.op_str
        if '[rip' in ops and '+' in ops:
            try:
                disp = int(ops.split('rip + ')[1].split(']')[0], 16)
                tgt = ins.address + ins.size + disp
                s = cstr(tgt)
                note = '  ; "%s"' % s if s else '  ; va=0x%x' % tgt
            except Exception:
                pass
        raw = '' if not args.hex else '  ' + pe.buf[off + (ins.address - args.va):
                                              off + (ins.address - args.va) + ins.size].hex()
        print('0x%x  %-8s %-42s%s%s' % (ins.address, ins.mnemonic, ops, note, raw))


if __name__ == '__main__':
    main()
