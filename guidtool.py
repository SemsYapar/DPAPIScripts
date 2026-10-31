#!/usr/bin/env python3
"""
guidtool.py — mkguid (16 raw bytes) <-> GUID string.

Windows GUID in memory: first 3 fields little-endian, last 2 fields big-endian.
"""
import struct

def guid_to_string(mkguid: bytes) -> str:
    """16 raw bytes -> 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' (master key file name)."""
    if len(mkguid) != 16:
        raise ValueError("mkguid must be 16 bytes")
    d1, d2, d3 = struct.unpack_from("<IHH", mkguid, 0)
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, mkguid[8:10].hex(), mkguid[10:16].hex())

def string_to_guid(s: str) -> bytes:
    """'xxxxxxxx-...' -> 16 raw bytes (inverse operation)."""
    p = s.strip("{}").split("-")
    return (struct.pack("<IHH", int(p[0], 16), int(p[1], 16), int(p[2], 16))
            + bytes.fromhex(p[3]) + bytes.fromhex(p[4]))

def parse_guid(s: str) -> bytes:
    """Accept either a dashed GUID ('xxxxxxxx-xxxx-...') or 32 hex chars -> 16 raw bytes."""
    t = s.strip().strip("{}")
    if "-" in t:
        return string_to_guid(t)
    raw = bytes.fromhex(t)
    if len(raw) != 16:
        raise ValueError("expected 16 bytes (32 hex chars) or a dashed GUID")
    return raw

def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Convert a DPAPI mkGUID between its string form and its 16 raw in-memory bytes.")
    ap.add_argument("value", help="a GUID string (xxxxxxxx-xxxx-...) or 16-byte hex; the other form is printed")
    a = ap.parse_args(argv)
    t = a.value.strip().strip("{}")
    if "-" in t:
        print(string_to_guid(t).hex())            # GUID string -> raw bytes (hex)
    else:
        raw = bytes.fromhex(t)
        if len(raw) != 16:
            ap.error("hex must be 16 bytes (32 chars)")
        print(guid_to_string(raw))                # raw bytes -> GUID string

if __name__ == "__main__":
    _main()