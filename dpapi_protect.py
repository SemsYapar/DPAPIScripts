#!/usr/bin/env python3
"""
dpapi_protect.py -- DPAPI data-blob protect/unprotect,
a model of dpapisrv!SPCryptProtect / SPCryptUnprotect (the persistent encryption behind CryptProtectData/CryptUnprotectData).

  root      = SHA1(masterKey) if len>20                       (FMyPrimitiveSHA)
  cipherKey = CryptDeriveKey( HMAC_root(salt||entropy||entropy2), keyLen )
  ciphertext= CBC_enc( cipherKey, IV=0, plaintext + block-pad )
  MAC       = HMAC_root( macSalt || entropy || entropy2 || blobBody )

Blob layout (the MAC covers mkversion..end-of-ciphertext, i.e. everything but the outer header):
  version(4) providerGUID(16) | mkversion(4) mkGUID(16) flags(4) | descrLen(4) descr |
  cipherAlgId(4) cipherKeyBits(4) | saltLen(4) salt | hmacKeyLen(4) hmacKey |
  hashAlgId(4) hashBits(4) | macSaltLen(4) macSalt | dataLen(4) ciphertext | signLen(4) MAC

Requires: pip install pycryptodome
"""

import struct, hashlib, hmac as _hmac
from Crypto.Cipher import AES, DES3

# ---------------- CALG tables ----------------
# cipher alg id -> (name, key bytes, block bytes)
CIPHER = {
    0x6610: ("AES-256", 32, 16),
    0x660f: ("AES-192", 24, 16),
    0x660e: ("AES-128", 16, 16),
    0x6603: ("3DES",    24, 8),
    0x6602: ("3DES-112",16, 8),
}
# hash alg id -> (name, hashlib ctor, digest bytes, block bytes)
HASH = {
    0x8004: ("SHA1",   hashlib.sha1,   20, 64),
    0x800c: ("SHA256", hashlib.sha256, 32, 64),
    0x800d: ("SHA384", hashlib.sha384, 48, 128),
    0x800e: ("SHA512", hashlib.sha512, 64, 128),
}

DPAPI_PROVIDER_GUID = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")

# ---------------- Flags ----------------
# DPAPI uses three distinct flag sets; keep them apart.
#
# (1) dwFlags on CryptProtectData / CryptUnprotectData  (CRYPTPROTECT_*, from dpapi.h):
class CryptProtectFlag:
    UI_FORBIDDEN      = 0x00000001   # forbid UI; enforced in the prompt-UI module
    LOCAL_MACHINE     = 0x00000004   # bind data to the machine, not the user
    CRED_SYNC         = 0x00000008   # NOT a data op -> triggers master-key synchronization
    AUDIT             = 0x00000010   # emit a protect/unprotect audit event
    NO_RECOVERY       = 0x00000020   # defined in dpapi.h; not acted on by the analyzed binaries
    VERIFY_PROTECTION = 0x00000040   # unprotect: advise if the blob is weaker than host policy
    CRED_REGENERATE   = 0x00000080   # SPCryptProtect routes this to a credential-regenerate path, not a data op
    SYSTEM            = 0x20000000   # internal çağrılarda anlamlıdır, öteki türlü s_SSCryptUnprotectData/s_SSCryptProtectData RPC dispatcher larında
                                     # tespit edilirse 0x57 invalid params hatası ile döner. SPCryptUnprotect/SPCryptProtect direkt çağrıldığında ise bu flag
                                     # checking aşamalarını atlar direkt şifrelemeye geçmeye sağlar 

# (2) dwPromptFlags inside CRYPTPROTECT_PROMPTSTRUCT  (CRYPTPROTECT_PROMPT_*):
class CryptProtectPromptFlag:
    ON_UNPROTECT   = 0x1
    ON_PROTECT     = 0x2
    STRONG         = 0x8
    REQUIRE_STRONG = 0x10

# name -> value for the CRYPTPROTECT_* namespace, for CLI flag selection
FLAGS = {n: getattr(CryptProtectFlag, n) for n in vars(CryptProtectFlag) if n.isupper()}

# (3) The flags field STORED INSIDE the blob (body offset +0x14). SPCryptProtect composes it
#     from both sets above and writes it.
_BLOB_FLAG_NAMES = [
    (0x00000001, "PROMPT_ON_UNPROTECT"),
    (0x00000002, "PROMPT_ON_PROTECT"),
    (0x00000004, "LOCAL_MACHINE"),
    (0x00000008, "PROMPT_STRONG"),
    (0x00000010, "AUDIT"),
    (0x20000000, "SYSTEM"),
]
_BLOB_FLAG_MASK = 0
for _bit, _ in _BLOB_FLAG_NAMES:
    _BLOB_FLAG_MASK |= _bit

def decode_dwflags(flags: int) -> list:
    """Names of the CRYPTPROTECT_* bits set in a dwFlags value (namespace 1)."""
    return [n for n, b in [("UI_FORBIDDEN",0x1),("LOCAL_MACHINE",0x4),("CRED_SYNC",0x8),
            ("AUDIT",0x10),("NO_RECOVERY",0x20),("VERIFY_PROTECTION",0x40),
            ("CRED_REGENERATE",0x80),("SYSTEM",0x20000000)] if flags & b]

def decode_blob_flags(flags: int) -> list:
    """
    Names of the bits set in a blob's stored flags field (namespace 3). In this field
    0x8 == PROMPT_STRONG and 0x4 == LOCAL_MACHINE -- do NOT read it as a dwFlags value.
    """
    names = [name for bit, name in _BLOB_FLAG_NAMES if flags & bit]
    unknown = flags & ~_BLOB_FLAG_MASK
    if unknown:
        names.append("UNKNOWN(%#x)" % unknown)
    return names

def describe_blob_flags(blob: bytes) -> dict:
    """
    Parse a DPAPI blob and report what its flags field holds, e.g.
        {"flags": 0x24, "names": ["LOCAL_MACHINE", "AUDIT"]}
    """
    f = parse_blob(blob)
    return {"flags": f["flags"], "names": decode_blob_flags(f["flags"])}

# ---------------- core helpers ----------------
def _prehash_masterkey(masterkey: bytes) -> bytes:
    """FMyPrimitiveSHA: if master key is longer than 20B, reduce to SHA1 (HMAC key)."""
    return hashlib.sha1(masterkey).digest() if len(masterkey) > 20 else masterkey

def _hmac_digest(root: bytes, hashctor, *chunks) -> bytes:
    h = _hmac.new(root, digestmod=hashctor)
    for c in chunks:
        if c:
            h.update(c)
    return h.digest()

def crypt_derive_key(digest: bytes, keylen: int, hashctor, blocklen: int) -> bytes:
    """
    CAPI CryptDeriveKey (BCryptDeriveKeyCapi). If keylen <= len(digest), simple
    truncation; otherwise a two-block expansion with 0x36/0x5c.
    """
    if keylen <= len(digest):
        return digest[:keylen]
    ipad = bytearray([0x36]) * blocklen
    opad = bytearray([0x5c]) * blocklen
    for i in range(len(digest)):
        ipad[i] ^= digest[i]
        opad[i] ^= digest[i]
    out = hashctor(bytes(ipad)).digest() + hashctor(bytes(opad)).digest()
    return out[:keylen]

def _derive_cipher_key(masterkey, salt, cipher_id, hash_id, entropy=b"", entropy2=b""):
    _, keylen, _ = CIPHER[cipher_id]
    _, hashctor, _, blocklen = HASH[hash_id]
    root = _prehash_masterkey(masterkey)
    dig  = _hmac_digest(root, hashctor, salt, entropy, entropy2)
    return crypt_derive_key(dig, keylen, hashctor, blocklen)

def _cbc(cipher_id, key, iv):
    _, _, blk = CIPHER[cipher_id]
    if cipher_id in (0x660e, 0x660f, 0x6610):
        return AES.new(key, AES.MODE_CBC, iv[:16]), blk
    return DES3.new(key, DES3.MODE_CBC, iv[:8]), blk

# ---------------- block padding (PKCS7, BCRYPT_BLOCK_PADDING) ----------------
def _pad(data, blk):
    n = blk - (len(data) % blk)
    return data + bytes([n]) * n

def _unpad(data, blk):
    n = data[-1]
    if n == 0 or n > blk:
        raise ValueError("invalid padding")
    return data[:-n]

# ---------------- blob parse ----------------
def parse_blob(blob: bytes) -> dict:
    o = 0
    def u32():
        nonlocal o; v = struct.unpack_from("<I", blob, o)[0]; o += 4; return v
    def take(n):
        nonlocal o; v = blob[o:o+n]; o += n; return v
    f = {}
    f["version"]  = u32()
    f["provider"] = take(16)
    sign_start_body = o                 # MAC starts here (mkversion)
    f["mkversion"] = u32()
    f["mkguid"]    = take(16)
    f["flags"]     = u32()
    dl = u32(); f["descr"] = take(dl)
    f["cipher_id"] = u32(); f["cipher_bits"] = u32()
    sl = u32(); f["salt"] = take(sl)
    hkl = u32(); f["hmac_key"] = take(hkl)
    f["hash_id"] = u32(); f["hash_bits"] = u32()
    msl = u32(); f["mac_salt"] = take(msl)
    dl2 = u32(); f["data"] = take(dl2)
    sign_body_end = o                   # MAC up to here (end of ciphertext)
    sgl = u32(); f["sign"] = take(sgl)
    f["_signed"] = blob[sign_start_body:sign_body_end]
    return f

# ---------------- UNPROTECT (decrypt a real blob) ----------------
def unprotect(blob: bytes, masterkey: bytes, entropy=b"", entropy2=b"", verify=True):
    """
    Returns (plaintext, descr_unicode, mac_ok). Only the RAW master key is needed;
    salt/macSalt/alg/ciphertext/MAC are read from inside the blob.
    """
    f = parse_blob(blob)
    cid, hid = f["cipher_id"], f["hash_id"]
    if cid not in CIPHER: raise ValueError("unknown cipher 0x%x" % cid)
    if hid not in HASH:   raise ValueError("unknown hash 0x%x" % hid)

    root = _prehash_masterkey(masterkey)
    _, hashctor, _, _ = HASH[hid]

    # verify MAC: HMAC_root( macSalt || entropy || entropy2 || blobBody )
    mac_ok = None
    if verify:
        mac = _hmac_digest(root, hashctor, f["mac_salt"], entropy, entropy2, f["_signed"])
        mac_ok = _hmac.compare_digest(mac[:len(f["sign"])], f["sign"])
        if not mac_ok:
            # wrong master key / entropy / tampering -> don't even decrypt (real behavior)
            return None, f["descr"].decode("utf-16-le", "replace").rstrip("\x00"), False

    # derive cipher key, decrypt, strip padding
    key = _derive_cipher_key(masterkey, f["salt"], cid, hid, entropy, entropy2)
    cipher, blk = _cbc(cid, key, b"\x00" * 16)
    plain = _unpad(cipher.decrypt(f["data"]), blk)
    descr = f["descr"].decode("utf-16-le", "replace").rstrip("\x00")
    return plain, descr, mac_ok

# ---------------- PROTECT (rebuild a blob) ----------------
def protect(plaintext, masterkey, mkguid, descr="", *,
            salt, mac_salt, cipher_id=0x6610, hash_id=0x800e,
            entropy=b"", entropy2=b"", flags=0):
    """
    To reproduce a real blob byte-for-byte, salt/mac_salt must be the REAL values
    (captured from the BCryptGenRandom outputs). To make a new blob you can pass
    random ones.

    `flags` is written verbatim into the blob's flags field. (How dwFlags maps onto that
    field inside SPCryptProtect is NOT established here -- r14d carries LOCAL_MACHINE/
    AUDIT/SYSTEM into crypto helper calls, but the blob-field write site was not located,
    so no masking is applied. For byte-for-byte reproduction pass the parsed f["flags"].)
    """
    cid, hid = cipher_id, hash_id
    _, keylen, blk = CIPHER[cid]
    root = _prehash_masterkey(masterkey)
    _, hashctor, _, _ = HASH[hid]

    # ciphertext
    key = _derive_cipher_key(masterkey, salt, cid, hid, entropy, entropy2)
    cipher, _ = _cbc(cid, key, b"\x00" * 16)
    data = cipher.encrypt(_pad(plaintext, blk))

    descr_b = (descr + "\x00").encode("utf-16-le") if descr is not None else b"\x00\x00"

    cipher_bits = keylen * 8
    hash_bits = HASH[hid][2] * 8

    # body from mkversion to the ciphertext (MAC is over this)
    body = b""
    body += struct.pack("<I", 1)                 # mkversion
    body += mkguid                               # 16
    body += struct.pack("<I", flags)
    body += struct.pack("<I", len(descr_b)) + descr_b
    body += struct.pack("<I", cid) + struct.pack("<I", cipher_bits)
    body += struct.pack("<I", len(salt)) + salt
    body += struct.pack("<I", 0)                 # hmacKeyLen = 0
    body += struct.pack("<I", hid) + struct.pack("<I", hash_bits)
    body += struct.pack("<I", len(mac_salt)) + mac_salt
    body += struct.pack("<I", len(data)) + data

    mac = _hmac_digest(root, hashctor, mac_salt, entropy, entropy2, body)

    blob  = struct.pack("<I", 1) + DPAPI_PROVIDER_GUID   # outer version + provider
    blob += body
    blob += struct.pack("<I", len(mac)) + mac
    return blob

# ---------------- blob breakdown (parse only, no key needed) ----------------
def print_blob(blob: bytes, title="DPAPI blob"):
    """Print every field of a DPAPI blob. Needs nothing but the blob itself: the
    mkGUID, salts, algorithms, ciphertext and MAC all live inside it."""
    from guidtool import guid_to_string
    f = parse_blob(blob)
    cipher = CIPHER.get(f["cipher_id"], ("?", 0, 0))[0]
    hashn  = HASH.get(f["hash_id"], ("?", None, 0, 0))[0]
    flags  = decode_blob_flags(f["flags"]) or ["(none)"]
    descr  = f["descr"].decode("utf-16-le", "replace").rstrip("\x00")
    print("%s - %d bytes" % (title, len(blob)))
    print("  version        :", f["version"])
    print("  provider       :", guid_to_string(f["provider"]),
          "(DPAPI)" if f["provider"] == DPAPI_PROVIDER_GUID else "(DIFFERENT)")
    print("  mk version     :", f["mkversion"])
    print("  master-key GUID:", guid_to_string(f["mkguid"]), "- the master key that protects this blob")
    print("  flags          : %#010x  %s" % (f["flags"], ", ".join(flags)))
    print("  description    : %r" % descr)
    print("  cipher         : %#06x  %s (%d bit)" % (f["cipher_id"], cipher, f["cipher_bits"]))
    print("  salt (%2d B)    : %s" % (len(f["salt"]), f["salt"].hex()))
    print("  hmac key (%d B) : %s" % (len(f["hmac_key"]), f["hmac_key"].hex() or "(empty)"))
    print("  hash           : %#06x  %s (%d bit)" % (f["hash_id"], hashn, f["hash_bits"]))
    print("  mac salt (%2d B): %s" % (len(f["mac_salt"]), f["mac_salt"].hex()))
    print("  ciphertext(%2dB): %s" % (len(f["data"]), f["data"].hex()))
    print("  MAC (%2d B)     : %s" % (len(f["sign"]), f["sign"].hex()))

def _mkguid_arg(s: str) -> bytes:
    """--mkguid value -> 16 raw bytes. Accepts a dashed GUID, 16-byte hex, or empty (all-zero)."""
    if not s:
        return b"\x00" * 16
    from guidtool import parse_guid
    return parse_guid(s)

def _main(argv=None):
    import argparse, os, sys
    ap = argparse.ArgumentParser(description="DPAPI data-blob protect / unprotect / parse-blob (offline).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pu = sub.add_parser("unprotect", help="decrypt a DPAPI blob")
    pu.add_argument("--master-key", required=True, metavar="HEX", help="64-byte master key, hex")
    pu.add_argument("--blob", required=True, metavar="HEX", help="hex-encoded DPAPI blob")
    pu.add_argument("--entropy", metavar="HEX", default="")
    pu.add_argument("--entropy2", metavar="HEX", default="")
    pu.add_argument("--out", metavar="FILE", help="write plaintext here instead of stdout")

    pb = sub.add_parser("parse-blob", help="parse a DPAPI blob and print its fields (no key needed)")
    pb.add_argument("--blob", required=True, metavar="HEX", help="hex-encoded DPAPI blob")

    pp = sub.add_parser("protect", help="build a new DPAPI blob")
    pp.add_argument("--master-key", required=True, metavar="HEX")
    pp.add_argument("--mkguid", default="", metavar="GUID",
                    help="master-key GUID as a dashed GUID or 16-byte hex (optional; at unprotect you "
                         "supply the key yourself, so this is informational — omitted → all-zero GUID)")
    gd = pp.add_mutually_exclusive_group(required=True)
    gd.add_argument("--data", help="plaintext string (UTF-8)"); gd.add_argument("--in", dest="infile", metavar="FILE")
    pp.add_argument("--descr", default="")
    pp.add_argument("--entropy", metavar="HEX", default="")
    pp.add_argument("--entropy2", metavar="HEX", default="")
    pp.add_argument("--flag", action="append", default=[], choices=sorted(FLAGS),
                    help="blob flag bit (CRYPTPROTECT_*), repeatable: " + ", ".join(sorted(FLAGS)))
    pp.add_argument("--flags", type=lambda x: int(x, 0), default=0, help="raw flags int written into the blob, OR'd with --flag")
    pp.add_argument("--cipher", type=lambda x: int(x, 0), default=0x6610)
    pp.add_argument("--hash", type=lambda x: int(x, 0), default=0x800e)
    pp.add_argument("--out", metavar="FILE", help="write the blob here instead of printing hex")

    a = ap.parse_args(argv)
    rd = lambda p: open(p, "rb").read()

    if a.cmd == "parse-blob":
        print_blob(bytes.fromhex(a.blob))

    elif a.cmd == "unprotect":
        blob = bytes.fromhex(a.blob)
        pt, descr, mac_ok = unprotect(blob, bytes.fromhex(a.master_key),
                                      entropy=bytes.fromhex(a.entropy), entropy2=bytes.fromhex(a.entropy2))
        print("[*] mac_ok:", mac_ok, " descr:", descr)
        if pt is None:
            print("[!] MAC failed -- wrong master key / entropy / entropy2, or tampered"); sys.exit(1)
        print("[*] plaintext (%d B): %s" % (len(pt), pt.hex()))
        if a.out: open(a.out, "wb").write(pt); print("[*] plaintext ->", a.out)
        else:     sys.stdout.buffer.write(pt)

    elif a.cmd == "protect":
        data = a.data.encode() if a.data is not None else rd(a.infile)
        mkguid = _mkguid_arg(a.mkguid)
        flags = a.flags
        for n in a.flag:
            flags |= FLAGS[n]
        blob = protect(data, bytes.fromhex(a.master_key), mkguid, a.descr,
                        salt=os.urandom(16), mac_salt=os.urandom(16), cipher_id=a.cipher, hash_id=a.hash,
                        entropy=bytes.fromhex(a.entropy), entropy2=bytes.fromhex(a.entropy2), flags=flags)
        if a.out: open(a.out, "wb").write(blob); print("[*] blob ->", a.out)
        else:     print(blob.hex())

if __name__ == "__main__":
    _main()