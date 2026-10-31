#!/usr/bin/env python3
r"""
lsa_secrets.py -- extract DPAPI_SYSTEM (and the other LSA secrets) straight from the
SECURITY + SYSTEM registry hive files. No third-party tools.

    python lsa_secrets.py --security SECURITY --system SYSTEM

Get the hives first (admin), they are locked while Windows runs:
    reg save HKLM\SECURITY SECURITY
    reg save HKLM\SYSTEM   SYSTEM

What it does (Win10/11 AES "LSP" scheme, matching lsasrv.dll):
    SYSKEY/bootkey   <- the JD/Skew1/GBG/Data key classes in SYSTEM, permuted
    LSA key          <- SECURITY\Policy\PolEKList, AES-decrypted with the bootkey
    each secret      <- SECURITY\Policy\Secrets\<name>\CurrVal, AES-decrypted with the LSA key
DPAPI_SYSTEM is printed as the 44-byte value plus its machine/user halves, ready to pass to
masterkey.py --dpapi-system.

Requires: pip install pycryptodome
"""
import os, sys, struct, hashlib
from Crypto.Cipher import AES

# ---- minimal regf (registry hive) reader -------------------------------------------------
_HBIN = 0x1000
def _cell(buf, rel):
    pos = _HBIN + rel
    size = -struct.unpack_from("<i", buf, pos)[0]
    return buf[pos + 4: pos + (size if size > 0 else 4)]
def _root(buf):
    return _cell(buf, struct.unpack_from("<I", buf, 0x24)[0])
def _nk_name(cell):
    flags = struct.unpack_from("<H", cell, 0x02)[0]
    nm = cell[0x4C:0x4C + struct.unpack_from("<H", cell, 0x48)[0]]
    return nm.decode("latin-1") if (flags & 0x20) else nm.decode("utf-16-le", "replace")
def _nk_class(buf, cell):
    clen = struct.unpack_from("<H", cell, 0x4A)[0]
    if clen == 0: return b""
    return _cell(buf, struct.unpack_from("<i", cell, 0x30)[0])[:clen]
def _subkeys(buf, cell):
    """yield (name, nk_cell) for each subkey."""
    cnt = struct.unpack_from("<I", cell, 0x14)[0]
    if cnt == 0: return
    offs = []
    def walk(rel):
        c = _cell(buf, rel); sig = c[0:2]
        if sig in (b"lf", b"lh"):
            for i in range(struct.unpack_from("<H", c, 2)[0]):
                offs.append(struct.unpack_from("<I", c, 4 + i*8)[0])
        elif sig == b"li":
            for i in range(struct.unpack_from("<H", c, 2)[0]):
                offs.append(struct.unpack_from("<I", c, 4 + i*4)[0])
        elif sig == b"ri":
            for i in range(struct.unpack_from("<H", c, 2)[0]):
                walk(struct.unpack_from("<I", c, 4 + i*4)[0])
    walk(struct.unpack_from("<i", cell, 0x1C)[0])
    for o in offs:
        c = _cell(buf, o)
        if c[0:2] == b"nk":
            yield _nk_name(c), c
def _find(buf, cell, name):
    for n, c in _subkeys(buf, cell):
        if n.lower() == name.lower(): return c
    return None
def _open(buf, parts):
    cell = _root(buf)
    for p in parts:
        cell = _find(buf, cell, p)
        if cell is None: raise KeyError("key not found: " + p)
    return cell
def _value(buf, cell, name):
    vcnt = struct.unpack_from("<I", cell, 0x24)[0]
    if vcnt == 0: return None
    vlist = _cell(buf, struct.unpack_from("<i", cell, 0x28)[0])
    for i in range(vcnt):
        vk = _cell(buf, struct.unpack_from("<I", vlist, i*4)[0])
        if vk[0:2] != b"vk": continue
        nlen  = struct.unpack_from("<H", vk, 0x02)[0]
        flags = struct.unpack_from("<H", vk, 0x10)[0]
        vname = vk[0x14:0x14+nlen].decode("latin-1") if (flags & 1) else vk[0x14:0x14+nlen].decode("utf-16-le","replace")
        if vname != name and not (name == "" and nlen == 0): continue
        dlen = struct.unpack_from("<I", vk, 0x04)[0]
        if dlen & 0x80000000: return vk[0x08:0x08 + (dlen & 0x7fffffff)]      # inline
        return _cell(buf, struct.unpack_from("<I", vk, 0x08)[0])[:dlen]
    return None

# ---- SYSKEY + LSA key + secret decryption ------------------------------------------------
_PERM = [0x8,0x5,0x4,0x2,0xb,0x9,0xd,0x3,0x0,0x6,0x1,0xc,0xe,0xa,0xf,0x7]
def bootkey(system_hive):
    sel = _value(system_hive, _open(system_hive, ["Select"]), "Current")
    cs  = "ControlSet%03d" % struct.unpack_from("<I", sel, 0)[0]
    hexstr = "".join(_nk_class(system_hive, _open(system_hive, [cs, "Control", "Lsa", n])).decode("utf-16-le")
                     for n in ("JD", "Skew1", "GBG", "Data"))
    scrambled = bytes.fromhex(hexstr)
    return bytes(scrambled[_PERM[i]] for i in range(16))

def _aes(key, blob):
    # lsasrv's scheme: aeskey = SHA256(key || blob[28:60] x1000); then each 16-byte block of
    # blob[60:] is AES-256 decrypted with IV=0 independently (no CBC chaining between blocks).
    h = hashlib.sha256(); h.update(key)
    for _ in range(1000): h.update(blob[28:60])
    aeskey = h.digest()
    data, out = blob[60:], b""
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) < 16: block += b"\x00" * (16 - len(block))
        out += AES.new(aeskey, AES.MODE_CBC, b"\x00"*16).decrypt(block)
    return out

def lsa_key(security_hive, bk):
    polek = _value(security_hive, _open(security_hive, ["Policy", "PolEKList"]), "")
    if not polek: raise KeyError("Policy\\PolEKList not found (pre-Win10 RC4 hive not supported)")
    return _aes(bk, polek)[68:100]

def secrets(security_hive, lk):
    """{name: raw secret bytes} for each secret under Policy\\Secrets.
    Layout: Policy\\Secrets\\<name>\\CurrVal is a KEY whose DEFAULT value is the encrypted blob."""
    out = {}
    sroot = _open(security_hive, ["Policy", "Secrets"])
    for name, cell in _subkeys(security_hive, sroot):
        cv = _find(security_hive, cell, "CurrVal")                           # CurrVal is a subkey
        if cv is None: continue
        enc = _value(security_hive, cv, "")                                  # its default value holds the blob
        if not enc: continue
        plain = _aes(lk, enc)
        length = struct.unpack_from("<I", plain, 0)[0]                       # LSA_SECRET_BLOB header
        out[name] = plain[16:16 + length]
    return out

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Extract DPAPI_SYSTEM (and other LSA secrets) from offline SECURITY + SYSTEM hives.")
    ap.add_argument("--security", required=True, metavar="FILE", help="HKLM\\SECURITY hive file")
    ap.add_argument("--system",   required=True, metavar="FILE", help="HKLM\\SYSTEM hive file")
    a = ap.parse_args(argv)
    security = open(a.security, "rb").read()
    system   = open(a.system, "rb").read()
    bk = bootkey(system)
    lk = lsa_key(security, bk)
    print(f"[*] bootkey : {bk.hex()}")
    print(f"[*] LSA key : {lk.hex()}\n")
    secs = secrets(security, lk)
    for name in sorted(secs):
        val = secs[name]
        print(f"=== {name}  ({len(val)} bytes) ===")
        print("   " + val.hex())
        if name == "DPAPI_SYSTEM" and len(val) >= 44:
            print(f"   version  : {struct.unpack_from('<I', val, 0)[0]}")
            print(f"   machine  : {val[4:24].hex()}")
            print(f"   user     : {val[24:44].hex()}")
            print(f"   -> DPAPI_SYSTEM_HEX = {val[:44].hex()}")
        print()
    return 0

if __name__ == "__main__":
    sys.exit(main())