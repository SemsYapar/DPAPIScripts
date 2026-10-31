# DPAPI Data Structures — Struct Reference

A field-by-field breakdown of every critical binary structure we parsed during
the analysis. For each structure: its real Windows/code name, offset table,
meaning, and the Python function that parses it. All multi-byte fields are
**little-endian** unless stated otherwise.

Quick mapping (code/colloquial name ↔ real name):

| Code / colloquial | Real structure name | Parsed by |
|---|---|---|
| "mkfile" | `MASTERKEY_STORED` file | `masterkey.parse_masterkey_stored` |
| "masterkey_blob" | `MASTERKEY_STORED.MasterKey` sub-blob | `masterkey.parse_masterkey_blob` |
| "DPAPI blob" | protected data blob (CryptProtectData output) | `dpapi_protect.parse_blob` |
| "pre-key" / DP_KEK | password-derived file-unlock key | `masterkey.derive_prekey` |
| CREDHIST | credential history file | `masterkey.parse_credhist` |
| SYNCHIST | sync history file | (non-crypto; §6) |
| Preferred | active master key pointer | (§7) |

---

## 1. GUID — memory/file layout

16 raw bytes. First three fields little-endian, last two big-endian (Windows GUID
convention). The **name** of a master key file is the string form of this GUID.

```
offset  size  field       encoding
+0x00   4     Data1       LE
+0x04   2     Data2       LE
+0x06   2     Data3       LE
+0x08   2     Data4[0:2]  BE (written in raw order)
+0x0a   6     Data4[2:8]  BE
```

String: `%08x-%04x-%04x-%s-%s`. Parsed by: `guidtool.guid_to_string` /
`string_to_guid`.

---

## 2. DPAPI data blob — `CryptProtectData` output

The persistent blob produced by `SPCryptProtect` and returned to the application.
The outer `version + provider GUID` header is added by `DPAPICryptProtectDataEx`;
the body (from `mkversion` onward) is produced by `SPCryptProtect`. **The MAC is
computed over the body from `mkversion` to the end of the ciphertext** (excluding
the outer header).

```
offset  size       field             description
+0x00   4          version           = 1
+0x04   16         providerGUID      {df9d8cd0-0115-11d1-8c7a-00c04fc297eb}
---- MAC starts here (body) ------------------------------------------------
        4          mkversion         = 1
        16         mkGUID            which master key it was encrypted with (→ file name)
        4          flags             composed by SPCryptProtect, written at body+0x14 (see below)
        4          descrLen          description length (bytes)
        descrLen   descr             UTF-16LE description (CRYPTPROTECT descr)
        4          cipherAlgId       0x6610=AES-256 / 0x660e=AES-128 / 0x6603=3DES
        4          cipherKeyBits
        4          saltLen
        saltLen    salt              cipher-key derivation salt
        4          hmacKeyLen        usually 0
        hmacKeyLen hmacKey
        4          hashAlgId         0x800e=SHA512 / 0x800c=SHA256 / 0x8004=SHA1
        4          hashBits
        4          macSaltLen
        macSaltLen macSalt           MAC salt
        4          dataLen
        dataLen    ciphertext        CBC, IV=0, block-pad
---- MAC ends here ---------------------------------------------------------
        4          signLen
        signLen    MAC               HMAC_root(macSalt‖entropy‖entropy2‖body)
```

Crypto (parsed by `dpapi_protect.parse_blob`, decrypted by `unprotect`):
```
root      = SHA1(masterkey)                         # if longer than 20B
cipherKey = CryptDeriveKey( HMAC_root(salt‖entropy‖entropy2), keyLen )
plaintext = CBC_decrypt(cipherKey, IV=0, ciphertext) ; block-pad stripped
MAC       = HMAC_root(macSalt‖entropy‖entropy2‖body)   # always verified
```

The `flags` field (body +0x14) is a MERGE of two namespaces, built by `SPCryptProtect` and
written at `@64f2`. Its bits (decoded by `dpapi_protect.decode_blob_flags`):

```
0x00000001  PROMPT_ON_UNPROTECT   from dwPromptFlags  (or edx,0x1 @730e)
0x00000002  PROMPT_ON_PROTECT     from dwPromptFlags  (or edx,0x2 @72ff)
0x00000004  LOCAL_MACHINE         from dwFlags        (r14d=0x4   @6b58)
0x00000008  PROMPT_STRONG         from dwPromptFlags  (or edx,0x8 @693c)   # NOT CRED_SYNC here
0x00000010  AUDIT                 from dwFlags        (and 0x20000010 @6034)
0x20000000  SYSTEM                from dwFlags        (and 0x20000010 @6034)
```

The low bits (0x1/0x2/0x8) are the prompt flags re-read on unprotect (crypt32 tests
`blob+0x28 & 0x1b`); 0x4/0x10/0x20000000 carry the LOCAL_MACHINE/AUDIT/SYSTEM dwFlags. The
dwFlags and dwPromptFlags namespaces are different: e.g. 0x8 is CRED_SYNC in dwFlags but
PROMPT_STRONG in this stored field.

---

## 3. MASTERKEY_STORED — master key file ("mkfile")

The GUID-named file at `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`. It holds a
**single master key**, but sealed in several ways (for recovery). Parsed by:
`masterkey.parse_masterkey_stored`.

```
offset  size    field         description
+0x00   4       version       = 2
+0x04   8       unk
+0x0c   72      guid          UTF-16LE string (same as the file name)
+0x54   8       unk
+0x5c   4       policy
+0x60   8       mkLen         MasterKey sub-blob length
+0x68   8       bkLen         BackupKey sub-blob length
+0x70   8       chLen         CredHist sub-blob length
+0x78   8       dkLen         DomainKey sub-blob length
+0x80   mkLen   MasterKey     user-sealed (with the password pre-key) → §4
        bkLen   BackupKey     local backup key (same master key, for recovery)
        chLen   CredHist      CREDHIST link (GUID)
        dkLen   DomainKey     domain backup key (RSA, MS-BKRP)
```

Note: `MasterKey`, `BackupKey` and `DomainKey` wrap the **same** 64B master key
with different keys — "one key, many seals". Having several **files** (different
GUIDs) is instead the result of **rotation** (~every 90 days), not the password.

---

## 3.5 pre-key (DP_KEK) — password-derived key

Not a file structure but a **derived key**; it unlocks the master key file (§4)
and the CREDHIST entries (§5). Called "pre-key" in code/colloquially, `DP_KEK` in
the dpapisrv signatures (DPAPI Key-Encryption-Key; `GetMasterKey` takes a `DP_KEK*`).

```
pwdhash = SHA1( password · UTF-16LE )            # credential key (MSV1_0); NTLM → MD4
pre_key = HMAC-SHA1( pwdhash, (SID+"\0")·UTF-16LE )   # 20 bytes; DeriveWithHMAC_SHA1
```

It is 20 bytes. It is **not** applied to the master key directly — it is the
password of `PKCS5DerivePBKDF2` (§4.1). The credential (pwdhash) is held in lsass,
from which dpapisrv obtains it; the plaintext password never arrives. Produced by:
`masterkey.prekey_from_password` / `derive_prekey`.

---

## 4. masterkey_blob — MASTERKEY_STORED.MasterKey sub-blob

The actual master key, sealed with the user's password. This is the structure
`decrypt_masterkey` sees. Parsed by: `masterkey.parse_masterkey_blob`.

```
offset  size    field         description
+0x00   4       version
+0x04   16      salt          PBKDF2 salt
+0x14   4       rounds        PBKDF2 round count (e.g. 8000)
+0x18   4       hashAlg       0x800e=SHA512 …
+0x1c   4       cipherAlg     0x6610=AES-256 …
+0x20   …       ciphertext    CBC; once decrypted ↓
```

Decrypted content (cleartext):
```
+0x00   16          hmacSalt
+0x10   digestLen   storedHmac     (SHA512 → 64B)
+..     64          masterkey      ← the actual 64B master key (LAST 64 bytes)
```

Crypto (verified live):
```
pre_key  = HMAC-SHA1( SHA1(password·UTF16LE), (SID+"\0")·UTF16LE )   # DeriveWithHMAC_SHA1
key‖iv   = PKCS5DerivePBKDF2( pre_key, salt, rounds )                # §4.1 — NOT standard
masterkey= CBC_decrypt(key, iv, ciphertext)[-64:]
verify   : HMAC( HMAC(pre_key, hmacSalt), masterkey ) == storedHmac
```

### 4.1 PKCS5DerivePBKDF2 — XOR-feedback variant (important!)

This is **not** standard PBKDF2. The difference (decompile + verified live):
standard feeds the previous U each round; this implementation feeds the
**accumulated XOR result (T)** and loops **rounds-1** times:
```
T = HMAC-SHA512(pre_key, salt ‖ INT32BE(i))          # U1, before the loop
(rounds-1) times:  T = T ⊕ HMAC-SHA512(pre_key, T)   # accumulated T fed back
```
Implemented by: `masterkey._pkcs5_derive_pbkdf2`. Live vector: `pre=7a1851b2…`,
`salt=f1db2307…`, `rounds=8000` → `mk=73201998…` (byte-for-byte with the kernel).

---

## 5. CREDHIST — credential history file

`%APPDATA%\Microsoft\Protect\CREDHIST`. A chain of old password hashes, used to
open master keys sealed under an old password after a password change. Entries
are oldest to newest, with a 24B footer at the end. Parsed by:
`masterkey.parse_credhist`.

```
File = [entry_0]…[entry_N] [footer(24B)]

footer (last 24B):
  +0x00  4    version
  +0x04  16   guid           current credential GUID
  +0x14  4    cbEntries      total bytes before the footer (= size of the entries)

entry:
  +0x00  4    version
  +0x04  16   guid
  +0x14  4    unk
  +0x18  4    revision
  +0x1c  4    hashAlg        0x800e=SHA512 …
  +0x20  4    rounds
  +0x24  4    sidLen
  +0x28  4    cipherAlg      0x6610=AES-256 …
  +0x2c  4    shaHashLen     = 20
  +0x30  4    ntHashLen      = 20 (real MD4 is 16B + 4 zero)
  +0x34  16   salt
  +0x44  sidLen  SID         raw SID (owner of this entry)
  +..    pad16(shaLen+ntLen)  ciphertext
```

Crypto (**same** path as the master key):
```
derived = HMAC-SHA1(pwdhash, SID)                    # pwdhash = this level's SHA1
key‖iv  = PKCS5DerivePBKDF2(derived, salt, rounds)   # §4.1 variant
cleartext = CBC_decrypt(...) = prev_sha1(20) ‖ prev_nt(16,+4 zero)
```
`prev_sha1` opens the previous (older) entry → the chain. Implemented by:
`decrypt_credhist_entry`, chain walk: `walk_credhist`.

Live verification (VM): current password 442026 → `prev_sha1 = SHA1("")`,
`prev_nt = MD4("")` → the old password was empty.

---

## 6. SYNCHIST — sync history file (non-crypto)

`%APPDATA%\Microsoft\Protect\<SID>\SYNCHIST`. **Not** a password store; a
**fingerprint** that tracks when the master keys were last synchronized with the
domain backup.

```
offset  size    field         description
+0x00   4       version       = 1
+0x04   4       hashAlg       = 0x800e (SHA512)
+0x08   4       len           = 0x40 (64)
+0x0c   64      hash          SHA-512 of the master key file
```

`GetMasterKeySyncHash → HashMasterKeyFile` produces the hash;
`IsMasterKeySyncRequired` compares it with SYNCHIST and, on a mismatch,
`SynchronizeMasterKeys` (domain backup) is triggered. There is no secret to
decrypt inside, so it adds no crypto capability to `masterkey.py`.

---

## 7. Preferred — active master key pointer

`%APPDATA%\Microsoft\Protect\<SID>\Preferred`, 24 bytes. Holds which master key
file is current (active) and when it expires.

```
offset  size    field         description
+0x00   16      guid          current master key GUID (→ file name to open)
+0x10   8       lastUpdate    FILETIME; rotation ~90 days later
```

`protect` always uses the master key from Preferred; `unprotect` uses the mkGUID
from **inside** the blob (which may be an older file — this is why old blobs still
decrypt). Parsed by: `guidtool.guid_to_string(open(Preferred).read()[:16])`.
