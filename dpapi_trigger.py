#!/usr/bin/env python3
r"""
dpapi_trigger.py  (run on Windows) -- drive DPAPI through dpapi.dll's NoUI exports directly,
so the second entropy (entropy2) can be passed on both protect and unprotect. The public
crypt32!CryptProtectData / CryptUnprotectData always call these with pvEntropy2=NULL, cbEntropy2=0,
so they can neither set nor honor a second entropy.

Signatures (x64, from dpapi.dll):
  dpapi!CryptProtectDataNoUI   @ export ord 1  (rva 0x1330)
  dpapi!CryptUnprotectDataNoUI @ export ord 4  (rva 0x1010)

Both exports take 9 arguments and forward (pvEntropy2, cbEntropy2) as a raw buffer+length
to the same internal server routine.

  CryptProtectDataNoUI:
    (pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags,
     pvEntropy2, cbEntropy2, pDataOut) -> BOOL
  CryptUnprotectDataNoUI:
    (pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags,
     pvEntropy2, cbEntropy2, pDataOut) -> BOOL

Arg roles that differ between the two:
  * arg2: protect = szDataDescr (LPCWSTR, IN);  unprotect = ppszDataDescr (LPWSTR*, OUT)
  * arg3 pOptionalEntropy is a DATA_BLOB* on both (cbData@+0, pbData@+8).
  * arg7 pvEntropy2 is a raw pointer (not a DATA_BLOB) + arg8 cbEntropy2 is its length.

A blob protected with entropy2 can only be unprotected by supplying the same entropy2, because
the server folds entropy2 into both the key derivation and the blob MAC (see dpapi_protect.py).

CRYPT_I_NEW_PROTECTION_REQUIRED (0x00091012) is an informational status: on success the call
returns TRUE and this code is reported via GetLastError(), and only when CRYPTPROTECT_VERIFY_
PROTECTION (0x40) was passed. It is never the return value.

  python dpapi_trigger.py protect   --text secret [--entropy e1] [--entropy2 e2] [--flag LOCAL_MACHINE ...]
  python dpapi_trigger.py unprotect --blob <blob_hex> [--entropy e1] [--entropy2 e2] [--flag VERIFY_PROTECTION]
"""
import ctypes, argparse, sys
from ctypes import wintypes
from dpapi_protect import CryptProtectFlag   # binary-derived flag values

# use_last_error=True so GetLastError is captured atomically by ctypes.
dpapi = ctypes.WinDLL("dpapi.dll", use_last_error=True)
kernel32 = ctypes.windll.kernel32

# name -> value for the dwFlags namespace (CRYPTPROTECT_*)
FLAGS = {n: getattr(CryptProtectFlag, n) for n in vars(CryptProtectFlag) if n.isupper()}

# Informational status surfaced via GetLastError() after a successful unprotect when
# CRYPTPROTECT_VERIFY_PROTECTION (0x40) is set. (wincrypt.h: 0x00091012L)
CRYPT_I_NEW_PROTECTION_REQUIRED = 0x00091012


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data):
    """Return (DATA_BLOB, keepalive_buffer) wrapping `data`."""
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _bytes(b):
    return ctypes.string_at(b.pbData, b.cbData) if b.cbData else b""


def _entref(data):
    """(byref DATA_BLOB or None, keepalive) for an optional pOptionalEntropy (arg3)."""
    if not data:
        return None, None
    b, buf = _blob(data)
    return ctypes.byref(b), (b, buf)


def _raw_entropy2(data):
    """(pvEntropy2 as c_void_p or None, cbEntropy2 int, keepalive) for arg7/arg8.

    entropy2 is a raw buffer+length: the server receives the pointer in one slot and
    the length in the next."""
    if not data:
        return None, 0, None
    buf = ctypes.create_string_buffer(data, len(data))
    return ctypes.cast(buf, ctypes.c_void_p), len(data), buf


# ---- CryptProtectDataNoUI: returns BOOL ----
dpapi.CryptProtectDataNoUI.restype = wintypes.BOOL
dpapi.CryptProtectDataNoUI.argtypes = [
    ctypes.POINTER(DATA_BLOB),       # 1. pDataIn
    wintypes.LPCWSTR,                # 2. szDataDescr        (IN)
    ctypes.POINTER(DATA_BLOB),       # 3. pOptionalEntropy
    ctypes.c_void_p,                 # 4. pvReserved
    ctypes.c_void_p,                 # 5. pPromptStruct
    wintypes.DWORD,                  # 6. dwFlags
    ctypes.c_void_p,                 # 7. pvEntropy2         (raw buffer)
    wintypes.DWORD,                  # 8. cbEntropy2
    ctypes.POINTER(DATA_BLOB),       # 9. pDataOut
]

# ---- CryptUnprotectDataNoUI: returns BOOL ----
dpapi.CryptUnprotectDataNoUI.restype = wintypes.BOOL
dpapi.CryptUnprotectDataNoUI.argtypes = [
    ctypes.POINTER(DATA_BLOB),       # 1. pDataIn
    ctypes.POINTER(wintypes.LPWSTR), # 2. ppszDataDescr      (OUT)
    ctypes.POINTER(DATA_BLOB),       # 3. pOptionalEntropy
    ctypes.c_void_p,                 # 4. pvReserved
    ctypes.c_void_p,                 # 5. pPromptStruct
    wintypes.DWORD,                  # 6. dwFlags
    ctypes.c_void_p,                 # 7. pvEntropy2         (raw buffer)
    wintypes.DWORD,                  # 8. cbEntropy2
    ctypes.POINTER(DATA_BLOB),       # 9. pDataOut
]


def protect(data, descr="", entropy=b"", entropy2=b"", flags=0):
    pIn, _k0 = _blob(data)
    pE, _k1 = _entref(entropy)
    pE2, cbE2, _k2 = _raw_entropy2(entropy2)

    out = DATA_BLOB()
    ok = dpapi.CryptProtectDataNoUI(
        ctypes.byref(pIn),              # 1 pDataIn
        descr or None,                  # 2 szDataDescr
        pE,                             # 3 pOptionalEntropy
        None,                           # 4 pvReserved
        None,                           # 5 pPromptStruct
        flags,                          # 6 dwFlags
        pE2,                            # 7 pvEntropy2
        cbE2,                           # 8 cbEntropy2
        ctypes.byref(out),              # 9 pDataOut
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    blob = _bytes(out)
    if out.pbData:
        kernel32.LocalFree(out.pbData)
    return blob


def unprotect(blob, entropy=b"", entropy2=b"", flags=0):
    pIn, _k0 = _blob(blob)
    pE, _k1 = _entref(entropy)
    pE2, cbE2, _k2 = _raw_entropy2(entropy2)
    descr = wintypes.LPWSTR()
    out = DATA_BLOB()

    ok = dpapi.CryptUnprotectDataNoUI(
        ctypes.byref(pIn),              # 1 pDataIn
        ctypes.byref(descr),            # 2 ppszDataDescr (OUT)
        pE,                             # 3 pOptionalEntropy
        None,                           # 4 pvReserved
        None,                           # 5 pPromptStruct
        flags,                          # 6 dwFlags
        pE2,                            # 7 pvEntropy2
        cbE2,                           # 8 cbEntropy2
        ctypes.byref(out),              # 9 pDataOut
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    # The call returns BOOL (1 = success). The CRYPT_I_NEW_PROTECTION_REQUIRED advisory is not
    # in the return value; the server reports it through SetLastError, and only when
    # CRYPTPROTECT_VERIFY_PROTECTION was requested. GetLastError is read only in that case.
    needs_new_protection = bool(flags & CryptProtectFlag.VERIFY_PROTECTION) and \
        ctypes.get_last_error() == CRYPT_I_NEW_PROTECTION_REQUIRED

    data = _bytes(out)
    d = descr.value
    if out.pbData:
        kernel32.LocalFree(out.pbData)
    if descr.value:
        kernel32.LocalFree(descr)

    return data, d, needs_new_protection


def _main(argv=None):
    ap = argparse.ArgumentParser(description="Drive DPAPI via dpapi.dll NoUI exports (entropy2 on both paths).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # ---- protect ----
    p_prot = sub.add_parser("protect")
    gi_prot = p_prot.add_mutually_exclusive_group(required=True)
    gi_prot.add_argument("--text")
    gi_prot.add_argument("--hex")
    p_prot.add_argument("--entropy", default="")
    p_prot.add_argument("--entropy2", default="")
    p_prot.add_argument("--flag", action="append", default=[], choices=sorted(FLAGS),
                        help="dwFlags bit (CRYPTPROTECT_*), repeatable: " + ", ".join(sorted(FLAGS)))
    p_prot.add_argument("--flags", type=lambda x: int(x, 0), default=0, help="raw dwFlags int, OR'd with --flag")
    p_prot.add_argument("--descr", default="")
    p_prot.add_argument("--out", metavar="FILE")

    # ---- unprotect ----
    p_unprot = sub.add_parser("unprotect")
    p_unprot.add_argument("--blob", required=True, help="hex-encoded encrypted blob")
    p_unprot.add_argument("--entropy", default="")
    p_unprot.add_argument("--entropy2", default="",
                          help="the same entropy2 used at protect time")
    p_unprot.add_argument("--flag", action="append", default=[], choices=sorted(FLAGS),
                          help="dwFlags bit (CRYPTPROTECT_*), repeatable; use VERIFY_PROTECTION for the advisory")
    p_unprot.add_argument("--flags", type=lambda x: int(x, 0), default=0, help="raw dwFlags int, OR'd with --flag")
    p_unprot.add_argument("--out", metavar="FILE")

    a = ap.parse_args(argv)

    flags = a.flags
    for n in a.flag:
        flags |= FLAGS[n]

    if a.cmd == "protect":
        data = a.text.encode() if a.text is not None else bytes.fromhex(a.hex)
        ent = a.entropy.encode() if a.entropy else b""
        ent2 = a.entropy2.encode() if a.entropy2 else b""
        blob = protect(data, a.descr, ent, ent2, flags)
        if a.out:
            open(a.out, "wb").write(blob); print("[*] blob ->", a.out)
        else:
            print(blob.hex())
    else:
        blob_data = bytes.fromhex(a.blob)
        ent = a.entropy.encode() if a.entropy else b""
        ent2 = a.entropy2.encode() if a.entropy2 else b""
        pt, descr, needs_new_protection = unprotect(blob_data, ent, ent2, flags)

        if descr:
            print("[*] descr:", descr)
        if needs_new_protection:
            print("[!] WARNING: CRYPT_I_NEW_PROTECTION_REQUIRED "
                "(blob contains a weaker algorithm/key than the default; re-protection is recommended)")
        if a.out:
            open(a.out, "wb").write(pt); print("[*] plaintext ->", a.out)
        else:
            sys.stdout.buffer.write(pt)


if __name__ == "__main__":
    _main()