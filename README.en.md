# Apex Legends: Transport Protection and the Limits of Passive Observation

English version · [中文版](README.md)

Reverse-engineering notes on how the Apex Legends client protects its match
transport, and on what a local-network gateway can and cannot learn from it.

> **Bottom line: a gateway-side tap cannot read match data.** This is not
> "we did not try hard enough" — it is the end of a chain whose last link is a
> per-match key delivered inside an authenticated TLS session. Seven paths were
> tested and closed, each with the observed evidence recorded.

---

## Why this repository exists

Most public writing on game networking says "I did it". Almost nobody writes
"I proved it cannot be done, and here is exactly where it breaks".

The second is more useful: it saves the next person months. This repository is
that second kind, plus a post-mortem of three reasoning errors made along the
way (see `docs/05`), which are common enough in reverse engineering to be worth
studying on their own.

---

## Findings

### 1. Datagram format

```
[12-byte random nonce][ciphertext N][16-byte tag]      total = N + 28
```

- encrypted length is always input + 0x1C (28 bytes)
- the nonce is generated per packet by `BCryptGenRandom`, not derived from a counter
- the construction is AEAD-class

See `docs/01-packet-format.md`.

### 2. Where the key comes from

The symmetric key is **not negotiated on the match channel**. It is handed to
the client at connection setup:

- path A: DTLS handshake → HKDF → 16-byte key installed
- path B: a string field in the connection-info structure → installed directly

Both run during connection establishment, and the key is rotated periodically
(visible as `new_key` events in plaintext telemetry).

See `docs/02-key-delivery.md`.

### 3. Why a gateway cannot get it

The client talks to the backend over TLS 1.2 and validates certificates against
an **embedded trust list**, not the OS certificate store:

- three pinned roots: DigiCert Global Root G2, GlobalSign Root CA, Amazon Root CA 1
- tested: installing a test CA into `LocalMachine\Root` and serving a fully
  compliant leaf certificate (serverAuth EKU, SAN, complete chain) — the client
  still aborts right after the ClientHello
- the `-insecure` launch flag does not change this

See `docs/03` and `docs/04`.

---

## What this repository does **not** contain

- no match data
- no radar / ESP / aimbot
- no packet captures (they contain account and LAN identifiers)
- no game binaries or vendor code
- no step-by-step "bypass the anti-cheat" guide

It is a defensive-side record: how the protection is built, and where the
boundary of passive observation lies.

---

## Layout

```
docs/
  01-packet-format.md          how the datagram layout was recovered
  02-key-delivery.md           where the key comes from
  03-anti-cheat-surface.md     ETW lockdown and process-right stripping
  04-negative-results.md       seven paths, tested and closed
  05-methodology-postmortem.md three evidence jumps, reviewed  <-- start here
  06-plaintext-telemetry.md    session timing from plaintext statsd
  07-boundary-analysis.md      why only kernel/hardware paths remain

tools/
  pe_tools.py           PE imports (incl. by-ordinal), IAT xrefs, signatures
  disasm_range.py       range disassembly with rip-relative annotation
  ntfs_extents.py       read kernel-locked files via the raw NTFS volume
  aead_oracle.py        AEAD tag as a 128-bit key oracle, plus blob scanning
  tls_pinning_probe.py  decide OS store vs pinned list
  pcapng_flows.py       flow summary and TLS SNI extraction
```

---

## Tool notes

### `pe_tools.py` — ordinal imports

`ws2_32.lib` exports `send`, `sendto`, `socket` and friends **by ordinal**. After
linking, the import table holds only numbers.

Any audit that reads import *names* alone will conclude "this binary cannot send
packets" on a program that obviously does. This tool resolves ordinals against
the real system DLL's export table.

That mistake is case #1 in `docs/05`.

### `aead_oracle.py` — a 128-bit predicate

```
non-AEAD : a wrong key may still produce something that "looks like plaintext"
AEAD     : tag verification; a wrong key cannot pass
```

So validating a candidate key needs no entropy, no thresholds, no human
judgement — one decryption settles it. The tool scans arbitrary blobs for
base64-shaped candidates and, optionally, brute-forces every 16-byte window.

### `ntfs_extents.py` — reading locked files

`pagefile.sys`, `hiberfil.sys` and `MEMORY.DMP` are held by the kernel and
cannot be opened. But the physical cluster list lives in the NTFS `$DATA`
attribute, and `\\.\C:` is readable by an administrator.

This tool walks the MFT, extracts the runlist, and reads those clusters
directly. Handles fragmented files and chunked reads.

---

## License

- code: MIT
- documents: CC BY 4.0

## Disclaimer

For protocol research and anti-cheat engineering reference. It contains no
implementation that could confer an unfair advantage in a game.
