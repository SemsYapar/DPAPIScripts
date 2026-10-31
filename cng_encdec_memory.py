#!/usr/bin/env python3
"""
cng_encdec_memory.py  (Windows)

KEY DERIVATION (scope x algorithm):
  AES  / SAME_PROCESS : SHA1(root || cookie4||createtime8)[:16]
  AES  / SAME_LOGON   : SHA1(root || LUID8)[:16]
  AES  / SYSTEM       : SHA1(root || 0x3e2(8B))[:16]
  AES  / CROSS_PROCESS: cross_key (16B) DIRECTLY  (g_AESKey; no SHA)
  3DES / SAME_PROCESS : SHA1(root||"aaa"||cookie4||time8)[:20] || SHA1(root||"bbb"||...)[:4]
  3DES / SAME_LOGON   : SHA1(root||"aaa"||LUID8)[:20]           || SHA1(root||"bbb"||LUID8)[:4]
  3DES / SYSTEM       : SHA1(root||"aaa"||0x3e2)[:20]           || SHA1(root||"bbb"||0x3e2)[:4]
  3DES / CROSS_PROCESS: root (24B) DIRECTLY as the 3DES key (g_DES3Key)
On SYSTEM decrypt, if caller LUID != 0x3e7 -> 0xC0000022.

ROOT MATERIAL (this boot's SystemPrng raw outputs, read from kernel memory):
  root24    (random #1, 24B) : SHA root + CROSS-3DES key
  cross_key (random #2, 16B) : CROSS-AES key
  iv        (random #3, 16B) : CBC IV

Requires: pip install pycryptodome
"""

import os
import ctypes
from ctypes import wintypes
import hashlib
from Crypto.Cipher import AES, DES3

# ---- NTSTATUS ----
STATUS_SUCCESS           = 0x00000000
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_ACCESS_DENIED     = 0xC0000022

class NtStatusError(Exception):
    def __init__(self, status):
        self.status = status & 0xFFFFFFFF
        super().__init__(f"NTSTATUS 0x{self.status:08X}")

# ---- Scope modes (OptionFlags / scope) ----
SAME_PROCESS, CROSS_PROCESS, SAME_LOGON, SYSTEM = 0, 1, 2, 4
_VALID_SCOPES = {SAME_PROCESS, CROSS_PROCESS, SAME_LOGON, SYSTEM}

LUID_SYSTEM     = 0x3E7   # cng: on decrypt the caller LUID is compared to this
SYSTEM_SCOPE_ID = 0x3E2   # cng: SYSTEM identity (constant)

# the two ASCII salts in 3DES derivation (GenerateKey): cng+0xa7000 / cng+0xa5c10
DES3_SALT_1 = b"aaa"
DES3_SALT_2 = b"bbb"

# ============================================================
# WINDOWS CONTEXT READERS (emulated off Windows)
# ============================================================
_CONTEXT_FALLBACK = (os.name != "nt")

if not _CONTEXT_FALLBACK:
    _k32 = ctypes.windll.kernel32
    _adv = ctypes.windll.advapi32
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.GetCurrentProcess.argtypes = []
    _k32.GetCurrentProcessId.restype = wintypes.DWORD
    _k32.GetCurrentProcessId.argtypes = []
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetProcessTimes.restype = wintypes.BOOL
    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_void_p]
    _adv.OpenProcessToken.restype = wintypes.BOOL
    _adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.HANDLE)]
    _adv.GetTokenInformation.restype = wintypes.BOOL
    _adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class TOKEN_STATISTICS(ctypes.Structure):
    _fields_ = [
        ("TokenId", LUID), ("AuthenticationId", LUID),
        ("ExpirationTime", wintypes.LARGE_INTEGER),
        ("TokenType", wintypes.DWORD), ("ImpersonationLevel", wintypes.DWORD),
        ("DynamicCharged", wintypes.DWORD), ("DynamicAvailable", wintypes.DWORD),
        ("GroupCount", wintypes.DWORD), ("PrivilegeCount", wintypes.DWORD),
        ("ModifiedId", LUID),
    ]

TOKEN_QUERY     = 0x0008
TokenStatistics = 10

def _auth_luid():
    hTok = wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(hTok)):
        raise ctypes.WinError()
    try:
        stats = TOKEN_STATISTICS()
        ret = wintypes.DWORD(0)
        if not _adv.GetTokenInformation(hTok, TokenStatistics, ctypes.byref(stats),
                                        ctypes.sizeof(stats), ctypes.byref(ret)):
            raise ctypes.WinError()
        a = stats.AuthenticationId
        return ((a.HighPart & 0xFFFFFFFF) << 32) | (a.LowPart & 0xFFFFFFFF)
    finally:
        _k32.CloseHandle(hTok)

def os_logon_id():
    # counterpart of SeQueryAuthenticationIdToken
    return LUID_SYSTEM if _CONTEXT_FALLBACK else _auth_luid()

def os_process_cookie():
    # counterpart of ZwQueryInformationProcess(ProcessCookie=0x24)
    return 0x1234 if _CONTEXT_FALLBACK else (_k32.GetCurrentProcessId() & 0xFFFFFFFF)

def os_process_create_time():
    # counterpart of PsGetProcessCreateTimeQuadPart (FILETIME 8B)
    if _CONTEXT_FALLBACK:
        return 0x01DB000000000000
    creation = wintypes.FILETIME(); dummy = wintypes.FILETIME()
    if not _k32.GetProcessTimes(_k32.GetCurrentProcess(),
                                ctypes.byref(creation), ctypes.byref(dummy),
                                ctypes.byref(dummy), ctypes.byref(dummy)):
        raise ctypes.WinError()
    return ((creation.dwHighDateTime << 32) | creation.dwLowDateTime) & 0xFFFFFFFFFFFFFFFF

def os_is_system():
    return os_logon_id() == LUID_SYSTEM

# ============================================================
# Root material of one boot session
# ============================================================
class Material:
    """
    root24     : random #1 raw (g_ShaHash buffer, cng+0xbf240) -- SHA root + CROSS-3DES
    iv16       : random #3 raw (RandomSalt,       cng+0xbf210) -- CBC IV
    cross_key16: random #2 raw (g_AESHash buffer, cng+0xbf1b0) -- CROSS-AES
    """
    def __init__(self, root24, iv16, cross_key16):
        if len(root24) != 24:      raise ValueError("root must be 24 bytes")
        if len(iv16) != 16:        raise ValueError("IV must be 16 bytes")
        if len(cross_key16) != 16: raise ValueError("cross_key must be 16 bytes")
        self.root = root24
        self.iv = iv16
        self.cross = cross_key16

# ============================================================
# Scope -> identity
# ============================================================
def scope_identity(scope, is_decrypt):
    if scope == SAME_PROCESS:
        return (os_process_cookie().to_bytes(4, "little") +
                os_process_create_time().to_bytes(8, "little"))      # 12B
    if scope == CROSS_PROCESS:
        return None                                                  # no identity
    if scope == SAME_LOGON:
        return os_logon_id().to_bytes(8, "little")                   # 8B LUID
    if scope == SYSTEM:
        if is_decrypt and not os_is_system():                        # caller LUID != 0x3e7
            raise NtStatusError(STATUS_ACCESS_DENIED)
        return SYSTEM_SCOPE_ID.to_bytes(8, "little")                 # 0x3e2, 8B
    raise NtStatusError(STATUS_INVALID_PARAMETER)

# ============================================================
# Key derivation
# ============================================================
def derive_aes_key(mat, scope, is_decrypt):
    # AES-128: outside CROSS, SHA1(root || identity)[:16]
    if scope == CROSS_PROCESS:
        scope_identity(scope, is_decrypt)       # (no side effect; for consistency)
        return mat.cross                         # g_AESKey = random #2 directly
    identity = scope_identity(scope, is_decrypt)
    h = hashlib.sha1(mat.root)
    if identity is not None:
        h.update(identity)
    return h.digest()[:16]

def derive_des3_key(mat, scope, is_decrypt):
    # 3DES: outside CROSS, salted double-SHA1 (GenerateKey):
    #   24B = SHA1(root||"aaa"||id)[:20] || SHA1(root||"bbb"||id)[:4]
    if scope == CROSS_PROCESS:
        scope_identity(scope, is_decrypt)
        return mat.root                          # g_DES3Key = root (random #1) directly
    identity = scope_identity(scope, is_decrypt)
    ident = identity if identity is not None else b""
    d1 = hashlib.sha1(mat.root + DES3_SALT_1 + ident).digest()   # 20B
    d2 = hashlib.sha1(mat.root + DES3_SALT_2 + ident).digest()   # 20B
    return d1 + d2[:4]                                            # 24B

# ============================================================
# Cipher
# ============================================================
def _crypt(mat, data, scope, encrypt):
    if scope not in _VALID_SCOPES:
        raise NtStatusError(STATUS_INVALID_PARAMETER)
    n = len(data)
    is_decrypt = not encrypt
    if n % 16 == 0:                              # AES-128-CBC, IV = RandomSalt (16B)
        key = derive_aes_key(mat, scope, is_decrypt)
        c = AES.new(key, AES.MODE_CBC, mat.iv)
        return c.encrypt(data) if encrypt else c.decrypt(data)
    if n % 8 == 0:                               # 3DES-CBC, IV = RandomSalt[:8]
        key = derive_des3_key(mat, scope, is_decrypt)
        c = DES3.new(key, DES3.MODE_CBC, mat.iv[:8])
        return c.encrypt(data) if encrypt else c.decrypt(data)
    raise NtStatusError(STATUS_INVALID_PARAMETER) # not even 8-aligned

def rtl_encrypt_memory(mat, data, option_flags):
    return _crypt(mat, data, option_flags, True)

def rtl_decrypt_memory(mat, data, option_flags):
    return _crypt(mat, data, option_flags, False)

# Helper to see which key it produces (diagnostic):
def show_key(mat, data_len, scope, is_decrypt=False):
    if data_len % 16 == 0:
        return ("AES-128", derive_aes_key(mat, scope, is_decrypt))
    if data_len % 8 == 0:
        return ("3DES",    derive_des3_key(mat, scope, is_decrypt))
    return ("INVALID", b"")

_SCOPES = {"same_process": SAME_PROCESS, "cross_process": CROSS_PROCESS,
           "same_logon": SAME_LOGON, "system": SYSTEM}

def _main(argv=None):
    import argparse, sys
    ap = argparse.ArgumentParser(description="RtlEncryptMemory/RtlDecryptMemory (SystemFunction04x) model. "
                                             "Needs this boot's kernel randoms (root/iv/cross).")
    ap.add_argument("op", choices=["encrypt", "decrypt"])
    ap.add_argument("--scope", choices=list(_SCOPES), default="same_logon")
    ap.add_argument("--root",  required=True, metavar="HEX", help="24-byte root (random #1)")
    ap.add_argument("--iv",    required=True, metavar="HEX", help="16-byte IV (random #3)")
    ap.add_argument("--cross", required=True, metavar="HEX", help="16-byte cross key (random #2)")
    gi = ap.add_mutually_exclusive_group(required=True)
    gi.add_argument("--in", dest="infile", metavar="FILE", help="read input bytes from a file")
    gi.add_argument("--hex", metavar="HEX", help="input as a hex string")
    gi.add_argument("--text", metavar="STR", help="input as UTF-8 text")
    ap.add_argument("--out", metavar="FILE", help="write result here instead of stdout hex")
    a = ap.parse_args(argv)

    mat = Material(bytes.fromhex(a.root), bytes.fromhex(a.iv), bytes.fromhex(a.cross))
    if a.infile:  data = open(a.infile, "rb").read()
    elif a.text:                                       # convenience: zero-pad text to the AES block (16)
        data = a.text.encode("utf-8")
        if len(data) % 16:
            data += b"\x00" * (16 - len(data) % 16)
            print("[*] padded input: %s" % data.hex())  # this is what actually gets encrypted
    else:         data = bytes.fromhex(a.hex)          # raw: misaligned input yields 0xC000000D, as the API does
    scope = _SCOPES[a.scope]
    try:
        out = rtl_encrypt_memory(mat, data, scope) if a.op == "encrypt" else rtl_decrypt_memory(mat, data, scope)
    except NtStatusError as e:
        print("[!]", e); sys.exit(1)
    if a.out: open(a.out, "wb").write(out); print("[*] %sed (%s) -> %s" % (a.op, show_key(mat, len(data), scope)[0], a.out))
    else:     print(out.hex())

if __name__ == "__main__":
    _main()