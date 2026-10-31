#!/usr/bin/env python3
"""
masterkey.py

Encryption/decryption of the DPAPI master key ITSELF -- i.e. sealing and
unsealing the master key held inside the on-disk MASTERKEY_STORED structure.
This is SEPARATE from encrypting data blobs (dpapi_protect.py): here the thing
being encrypted is the master key itself.

The algorithm was read LINE BY LINE from dpapisrv.dll!DecryptMasterKeyToMemoryEx
(PKCS5DerivePBKDF2 -> BCryptGenerateSymmetricKey -> BCryptDecrypt -> HMAC verify):

  key||iv   = PKCS5DerivePBKDF2( pre_key, salt=blob[4:20], rounds )   [keyLen+ivLen]
  cleartext = AES-256-CBC-decrypt( key, iv, ciphertext )
  cleartext = hmacSalt(16) || storedHmac(digestLen) || masterkey(64)
  verify    : HMAC( HMAC(pre_key, hmacSalt), masterkey ) == storedHmac
  -> master key (64B)

"pre_key" (DP_KEK) is the key that unlocks the file. For a user it comes from the
password: pwdhash = SHA1(password), pre_key = HMAC-SHA1(pwdhash, SID) (NT hash for
domain accounts). It is the password of the PKCS5DerivePBKDF2 above, not applied to
the master key directly. After a password change the file may still be sealed under
an old password's pre_key -- walk CREDHIST to get the old hashes and try each.

Requires: pip install pycryptodome
"""

import os, struct, hashlib, hmac as _hmac
from Crypto.Cipher import AES, DES3

# CALG id -> (name, keyLen, ivLen)   [cipher]
CIPHER = {0x6610:("AES-256",32,16), 0x660e:("AES-128",16,16), 0x6603:("3DES",24,8)}
# CALG id -> (name, hashlib-name, digestLen)   [PBKDF2 PRF + HMAC]
HASH   = {0x8004:("SHA1","sha1",20), 0x800c:("SHA256","sha256",32), 0x800e:("SHA512","sha512",64)}

MK_LEN = 64   # master key is always 64 bytes

# ============================================================
# pre-key (DP_KEK) : derivation from the password
#   ComputeMasterKeyUserEncryptionKey -> DeriveWithHMAC_SHA1
# ============================================================
def pwdhash_local(password: str) -> bytes:
    return hashlib.sha1(password.encode("utf-16-le")).digest()          # credential key

def pwdhash_ntlm(password: str) -> bytes:                                # NT hash
    data = password.encode("utf-16-le")
    try:
        return hashlib.new("md4", data).digest()          # older OpenSSL
    except ValueError:
        from Crypto.Hash import MD4                         # modern Python (OpenSSL3 dropped md4)
        return MD4.new(data).digest()

def derive_prekey(pwdhash: bytes, sid: str) -> bytes:
    """DP_KEK = HMAC-SHA1(pwdhash, (SID + \\0) UTF-16LE)."""
    return _hmac.new(pwdhash, (sid + "\x00").encode("utf-16-le"), hashlib.sha1).digest()

def prekey_from_password(password: str, sid: str, ntlm: bool = False) -> bytes:
    ph = pwdhash_ntlm(password) if ntlm else pwdhash_local(password)
    return derive_prekey(ph, sid)

# Machine/system accounts have no password: a 20-byte half of the DPAPI_SYSTEM secret IS the
# pre-key, used directly (no HMAC/SID step). Per dpapisrv!GetMasterKeyUserEncryptionKey,
# this raw-half path covers LOCAL_MACHINE and kinds 0x12/0x13/0x14 (SYSTEM/LocalService/
# NetworkService); only 0x5a/0x5b/0x63 use HMAC-SHA1(half, username). Machine half for
# LOCAL_MACHINE keys, user half otherwise. Secret comes from outside (lsa_secrets.py / LSA).
def parse_dpapi_system(secret: bytes):
    """DPAPI_SYSTEM (version(4)+machine(20)+user(20)) -> (machine_half, user_half); each is a pre-key."""
    if len(secret) < 44:
        raise ValueError("DPAPI_SYSTEM secret too short (need 44 bytes: 4+20+20)")
    return secret[4:24], secret[24:44]

# ============================================================
# On-disk structures: MASTERKEY_STORED file -> parse_masterkey_stored (gives masterkey_blob);
# masterkey_blob -> parse/build_masterkey_blob.
# ============================================================
def parse_masterkey_stored(data: bytes) -> dict:
    """GUID-named MASTERKEY_STORED file; pass f["masterkey_blob"] (not the whole file) to decrypt.
      version(4) unk(8) guid(72 UTF-16) unk(8) policy(4) mkLen(8) bkLen(8) chLen(8) dkLen(8) + 4 sub-blobs"""
    o = 0
    def u32():
        nonlocal o; v = struct.unpack_from("<I", data, o)[0]; o += 4; return v
    def u64():
        nonlocal o; v = struct.unpack_from("<Q", data, o)[0]; o += 8; return v
    f = {}
    f["version"] = u32(); o += 8
    f["guid"] = data[o:o+72].decode("utf-16-le").rstrip("\x00"); o += 72
    o += 8
    f["policy"] = u32()
    mkLen = u64(); bkLen = u64(); chLen = u64(); dkLen = u64()
    f["masterkey_blob"] = data[o:o+mkLen]; o += mkLen
    f["backupkey_blob"] = data[o:o+bkLen]; o += bkLen
    f["credhist"]       = data[o:o+chLen]; o += chLen
    f["domainkey_blob"] = data[o:o+dkLen]; o += dkLen
    return f

def parse_masterkey_blob(blob: bytes) -> dict:
    # version(4) salt(16) rounds(4) hashAlg(4) cipherAlg(4) ciphertext(...)
    ver, = struct.unpack_from("<I", blob, 0)
    salt = blob[4:20]
    rounds, hid, cid = struct.unpack_from("<III", blob, 20)
    return dict(version=ver, salt=salt, rounds=rounds, hash_id=hid,
                cipher_id=cid, ciphertext=blob[32:])

def build_masterkey_blob(salt, rounds, hash_id, cipher_id, ciphertext, version=2) -> bytes:
    return (struct.pack("<I", version) + salt +
            struct.pack("<III", rounds, hash_id, cipher_id) + ciphertext)

# ============================================================
# Core
# ============================================================
def _pkcs5_derive_pbkdf2(pwd, salt, rounds, dklen, prf):
    """
    dpapisrv!PKCS5DerivePBKDF2 -- NOT standard PBKDF2. The difference (from the
    decompile, confirmed live): instead of the previous U, each round feeds back
    the accumulated XOR result (T), and it loops rounds-1 times:
        T = HMAC(pwd, salt || INT32BE(i))
        (rounds-1) times:  T = T XOR HMAC(pwd, T)
    """
    ctor = getattr(hashlib, prf)
    out = b""; i = 1
    while len(out) < dklen:
        T = _hmac.new(pwd, salt + i.to_bytes(4, "big"), ctor).digest()
        for _ in range(rounds - 1):
            u = _hmac.new(pwd, T, ctor).digest()
            T = bytes(a ^ b for a, b in zip(T, u))
        out += T; i += 1
    return out[:dklen]

def _derive_keyiv(pre_key, salt, rounds, cipher_id, hash_id):
    _, keylen, ivlen = CIPHER[cipher_id]
    _, prf, _ = HASH[hash_id]
    km = _pkcs5_derive_pbkdf2(pre_key, salt, rounds, keylen + ivlen, prf)
    return km[:keylen], km[keylen:keylen+ivlen]

def _cipher(cipher_id, key, iv):
    if cipher_id in (0x6610, 0x660e):
        return AES.new(key, AES.MODE_CBC, iv[:16])
    return DES3.new(key, DES3.MODE_CBC, iv[:8])

def _mk_hmac(pre_key, hmac_salt, masterkey, hash_id):
    _, prf, _ = HASH[hash_id]
    ctor = getattr(hashlib, prf)
    inner = _hmac.new(pre_key, hmac_salt, ctor).digest()
    return _hmac.new(inner, masterkey, ctor).digest()

# ============================================================
# DECRYPT (unseal) : masterkey_blob + pre_key -> master key
# ============================================================
def decrypt_masterkey(masterkey_blob: bytes, pre_key: bytes):
    """
    Returns (master_key_64B, ok).  ok=True means the HMAC held -> pre_key is right.
    ok=False means pre_key does not open this file (wrong/old password -> CREDHIST).
    Pass parse_masterkey_stored(...)["masterkey_blob"], NOT the whole file.
    """
    f = parse_masterkey_blob(masterkey_blob)
    cid, hid = f["cipher_id"], f["hash_id"]
    if cid not in CIPHER: raise ValueError("cipher 0x%x? (did you pass the raw masterkey_blob?)" % cid)
    if hid not in HASH:   raise ValueError("hash 0x%x?" % hid)
    _, _, dl = HASH[hid]
    key, iv = _derive_keyiv(pre_key, f["salt"], f["rounds"], cid, hid)
    cleartext = _cipher(cid, key, iv).decrypt(f["ciphertext"])
    hmac_salt   = cleartext[:16]
    stored_hmac = cleartext[16:16+dl]
    masterkey   = cleartext[-MK_LEN:]
    calc = _mk_hmac(pre_key, hmac_salt, masterkey, hid)
    return masterkey, _hmac.compare_digest(calc, stored_hmac)

# ============================================================
# ENCRYPT (seal) : master key + pre_key -> masterkey_blob
# ============================================================
def encrypt_masterkey(masterkey: bytes, pre_key: bytes, *, salt=None, hmac_salt=None,
                      rounds=8000, cipher_id=0x6610, hash_id=0x800e, version=2) -> bytes:
    """
    Re-seal the master key under pre_key (produce a masterkey_blob for the file).
    salt/hmac_salt are random if not given. decrypt_masterkey(encrypt_masterkey(mk,pk),pk) == mk.
    """
    if len(masterkey) != MK_LEN: raise ValueError("master key must be 64 bytes")
    salt      = salt      or os.urandom(16)
    hmac_salt = hmac_salt or os.urandom(16)
    h = _mk_hmac(pre_key, hmac_salt, masterkey, hash_id)
    cleartext = hmac_salt + h + masterkey          # 16 + dl + 64  (AES256/SHA512: 144, block-aligned)
    key, iv = _derive_keyiv(pre_key, salt, rounds, cipher_id, hash_id)
    ciphertext = _cipher(cipher_id, key, iv).encrypt(cleartext)
    return build_masterkey_blob(salt, rounds, hash_id, cipher_id, ciphertext, version)

# ============================================================
# CREDHIST : password-history chain   (verified live)
#   %APPDATA%\Microsoft\Protect\CREDHIST
#   [entry_0]...[entry_N][footer(24)]  (oldest to newest; 24B footer at the end)
#   Footer (last 24B): version(4) guid(16) cbEntries(4 = total bytes before footer)
#   Entry format (from DecryptCredentialHistory decompile + verified against a real file):
#     +0x00 version  +0x04 guid(16)  +0x14 unk(4)  +0x18 revision(4)
#     +0x1c hashAlg  +0x20 rounds  +0x24 sidLen  +0x28 cipherAlg
#     +0x2c shaHashLen  +0x30 ntHashLen  +0x34 salt(16)
#     +0x44 SID(sidLen)  +0x44+sidLen ciphertext( pad16(shaLen+ntLen) )
#   Crypto is the SAME path as the master key: derived = HMAC-SHA1(pwdhash, SID),
#   key||iv = _pkcs5_derive_pbkdf2(derived, salt, rounds)  (XOR-feedback variant),
#   AES/3DES-CBC. Plaintext = prev_sha1(20) || prev_nt(16,+4 zero) = previous password's hashes.
# ============================================================
def _sid_to_str(raw: bytes) -> str:
    rev = raw[0]; cnt = raw[1]; auth = int.from_bytes(raw[2:8], "big")
    subs = [struct.unpack_from("<I", raw, 8+4*i)[0] for i in range(cnt)]
    return "S-%d-%d-%s" % (rev, auth, "-".join(map(str, subs)))

def parse_credhist(data: bytes) -> dict:
    """Split the CREDHIST file into entries + footer. Empty file (24B) -> entries=[]."""
    end = len(data) - 24
    fver, = struct.unpack_from("<I", data, end)
    fguid = data[end+4:end+20]
    cb,   = struct.unpack_from("<I", data, end+20)            # total bytes before footer
    entries = []
    o = 0
    while o < end:
        hashAlg, rounds, sidLen, cipherAlg, shaLen, ntLen = \
            struct.unpack_from("<IIIIII", data, o + 0x1c)
        salt = data[o+0x34:o+0x44]
        sid  = data[o+0x44:o+0x44+sidLen]
        ct_off = o + 0x44 + sidLen
        ct_len = (shaLen + ntLen + 15) & ~15                  # CBC block (16) alignment
        entries.append(dict(
            version=struct.unpack_from("<I",data,o)[0], guid=data[o+4:o+0x14],
            revision=struct.unpack_from("<I",data,o+0x18)[0], hash_id=hashAlg, rounds=rounds,
            sid_len=sidLen, cipher_id=cipherAlg, sha_len=shaLen, nt_len=ntLen,
            salt=salt, sid=sid, sid_str=_sid_to_str(sid),
            ciphertext=data[ct_off:ct_off+ct_len]))
        o = ct_off + ct_len
    return dict(entries=entries, footer_version=fver, footer_guid=fguid, cb_entries=cb)

def decrypt_credhist_entry(entry: dict, pwdhash: bytes, sid: str = None):
    """
    Decrypt the entry with THIS level's password SHA1 hash (20B). Returns
    (prev_sha1(20B), prev_nt(16B)) = the SHA1 and NT hashes of the PREVIOUS (older)
    password in the chain. Same derivation + KDF as the master key.
    """
    sid = sid or entry["sid_str"]
    derived = derive_prekey(pwdhash, sid)                     # HMAC-SHA1(pwdhash, SID)
    key, iv = _derive_keyiv(derived, entry["salt"], entry["rounds"],
                            entry["cipher_id"], entry["hash_id"])
    pt = _cipher(entry["cipher_id"], key, iv).decrypt(entry["ciphertext"])
    sha = pt[:20]
    nt  = pt[entry["sha_len"]:entry["sha_len"]+16]            # NT hash is really 16B (+4 zero padding)
    return sha, nt

def walk_credhist(credhist_bytes: bytes, current_pwdhash: bytes):
    """
    Starting from the current password's SHA1 hash, walk the chain NEWEST to
    OLDEST; each step yields that level's (sha1, nt) hashes. prev_sha1 opens the
    next (older) entry. From these hashes you can produce old pre-keys with
    derive_prekey(sha1, sid) and decrypt_masterkey master keys sealed under old passwords.
    """
    ch = parse_credhist(credhist_bytes)
    pwdhash = current_pwdhash
    for entry in reversed(ch["entries"]):                     # newest -> oldest
        sha, nt = decrypt_credhist_entry(entry, pwdhash)
        yield sha, nt
        pwdhash = sha


def _main(argv=None):
    import argparse, sys
    ap = argparse.ArgumentParser(description="Decrypt a DPAPI MASTERKEY_STORED file to its 64-byte master key.")
    ap.add_argument("masterkey_file", help="GUID-named MASTERKEY_STORED file")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--password", help="account password (ordinary user)")
    g.add_argument("--dpapi-system", metavar="HEX", help="44-byte DPAPI_SYSTEM secret, hex (machine/system account)")
    ap.add_argument("--sid", help="user SID (required with --password)")
    ap.add_argument("--ntlm", action="store_true", help="derive from the NT hash instead of SHA1 (domain accounts)")
    ap.add_argument("--local-machine", action="store_true",
                    help="with --dpapi-system: use the machine half (LOCAL_MACHINE keys); default is the user half")
    ap.add_argument("--credhist", metavar="FILE", help="with --password: CREDHIST file, to try old passwords too")
    a = ap.parse_args(argv)

    mk_blob = parse_masterkey_stored(open(a.masterkey_file, "rb").read())["masterkey_blob"]

    if a.dpapi_system:
        machine, user = parse_dpapi_system(bytes.fromhex(a.dpapi_system))
        half = machine if a.local_machine else user
        mk, ok = decrypt_masterkey(mk_blob, half)                       # raw half is the pre-key
        how = "DPAPI_SYSTEM %s half" % ("machine" if a.local_machine else "user")
    else:
        if not a.sid:
            ap.error("--password requires --sid")
        mk, ok = decrypt_masterkey(mk_blob, prekey_from_password(a.password, a.sid, a.ntlm))
        how = "current password"
        if not ok and a.credhist:
            cur = pwdhash_ntlm(a.password) if a.ntlm else pwdhash_local(a.password)
            for sha1, _nt in walk_credhist(open(a.credhist, "rb").read(), cur):
                mk, ok = decrypt_masterkey(mk_blob, derive_prekey(sha1, a.sid))
                if ok:
                    how = "CREDHIST (old password)"; break

    if not ok:
        print("[!] master key not recovered (wrong credential?)"); sys.exit(1)
    print("[*] opened with: %s" % how)
    print("[*] master key : %s" % mk.hex())

if __name__ == "__main__":
    _main()