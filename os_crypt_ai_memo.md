# CryptProtectData / CryptUnprotectData — Reverse Engineering Analysis

The full internals of the `CryptProtectData` / `CryptUnprotectData` paths: starting
from the calling application through the `dpapi.dll` client stub, the
`RtlEncryptMemory` transit protection (cng.sys/kernel), the RPC transport, and the
`dpapisrv.dll` server inside `lsass.exe`. Resolved with Ghidra/capstone decompilation
(public PDB symbols applied) + live KDNET kernel-debug observations.

Three separate binaries are involved:

| Module | Where it runs | Role | ImageBase |
|---|---|---|---|
| `dpapi.dll` | calling process | client stub: padding + transit + RPC client | 0x180000000 |
| `cng.sys` | kernel | transit crypto (`RtlEncrypt/DecryptMemory`) | 0x1c0000000 |
| `dpapisrv.dll` | inside `lsass.exe` | RPC server: persistent DPAPI crypto with the master key | 0x180000000 |

cng.sys symbols/offsets are for build `10.0.26100.1150`; dpapisrv.dll offsets are
specific to the copy in this analysis (ImageBase 0x180000000) and are all confirmed
from the public PDB table.

---

## 1. The Big Picture

There are two separate axes, not to be confused:

| Axis | Purpose | Key | Where it's encrypted | Lifetime |
|---|---|---|---|---|
| **DPAPI** (`CryptProtectData`) | Persistent data protection | Master key (password-derived) | `protected_storage` (lsass/dpapisrv) | Persistent (survives reboot) |
| **RtlEncryptMemory** | Transit / in-process protection | Root material (random, volatile) | cng.sys (kernel) | Volatile (dies at reboot) |

`CryptProtectData` wraps the data temporarily with `RtlEncryptMemory` **before**
sending it to lsass over RPC (LPC transit protection). The two run back-to-back in
the same call chain but do different jobs:

- **Transit axis** (cng.sys): prevents eavesdropping on the data traveling over
  ALPC between client and lsass. Fully modeled in §4–§6.
- **DPAPI axis** (dpapisrv/lsass): the actual persistent protection. The master
  key never reaches the caller; that is where the security boundary is. Covered in
  §2–§3 and §13.

---

## 2. CryptProtectData — High-Level Flow

```
 Application
    │ CryptProtectData(pDataIn, descr, entropy, ..., promptStruct, flags, pDataOut)
    ▼
 CryptProtectData              [crypt32.dll]
    │  - parameter validation; if descr NULL -> L""; prompt flag (flags & 3) -> UI path
    ├─ (flags & 3) ? -> UI dispatcher -> CryptProtectPromptUI (separate, registered OID module)
    ▼
 CryptProtectDataNoUI          [dpapi.dll, delay-loaded, ord 1 @0x1330]
    │  - padding to a multiple of 8 (last byte = padding length)
    │  - in-place transit encryption with RtlEncryptMemory (SystemFunction040, SAME_LOGON)
    │  - RpcStringBindingComposeW("ncalrpc","protected_storage") -> RpcBindingFromStringBindingW
    │  - NdrClientCall3(&ProxyInfo, procnum=0, NULL, hBinding)  -> ALPC, WAITS for the reply
    ▼  ncalrpc:[protected_storage], opnum 0
 protected_storage service     [dpapisrv.dll inside lsass.exe]
    │  - ProtectCallback (caller filter) -> NdrServerCall2 -> s_SSCryptProtectData
    │  - SPCryptProtect: opens the transit envelope with RtlDecryptMemory (SystemFunction041)
    │  - GetPreferredMasterKey -> does the actual, persistent DPAPI encryption with the MASTER KEY
    │  - prepends a 0x14 header: version(1) ‖ provider GUID {DF9D8CD0-…}
    ▼
 Application (pDataOut = persistent DPAPI blob)
```

`CryptUnprotectData` is the reverse of the same chain (opnum 1): the application
makes the RPC call, lsass decrypts with the master key and returns the plaintext
wrapped in transit, and the client opens the transit envelope with
`SystemFunction041` and strips the padding.

Key points:
- `CryptProtectDataNoUI` does **not** do the persistent crypto itself; only padding +
  transit protection + RPC. The real, persistent encryption is in lsass (dpapisrv).
- The master key **never** reaches the calling process; it is derived from the
  password and kept in lsass. That is the source of the security boundary.
- The prompt (UI) is a separate, pluggable OID module.

---

## 3. RPC Interface (protected_storage) — Client, Transport, Server

### 3.1 Client stub (dpapi.dll)

`CryptProtectDataNoUI` (ord 1) and `CryptUnprotectDataNoUI` (ord 4) set up the
binding by hand; the endpoint is **in the binding, not in the interface struct**:

```c
RpcStringBindingComposeW(NULL, L"ncalrpc", NULL, L"protected_storage", NULL, &str);
RpcBindingFromStringBindingW(str, &hBinding);
...
CVar = NdrClientCall3(&ProxyInfo /*PTR_PTR_180003000*/, procnum, NULL, hBinding);
//                                                        protect=0 / unprotect=1
```

`NdrClientCall3` arguments:

| Arg | Reg | Value | Meaning |
|---|---|---|---|
| pProxyInfo | rcx | `&ProxyInfo` | MIDL_STUBLESS_PROXY_INFO (interface + format strings) |
| nProcNum | edx | 0 / 1 | opnum (protect / unprotect) |
| pReturnValue | r8 | NULL | return-value target |
| arg4… | r9+stack | hBinding, … | the actual RPC arguments |

The client **blocks and waits** until the `NdrClientCall3` reply arrives
(`NtAlpcSendWaitReceivePort`).

### 3.2 Interface identity — GUID vs endpoint

The identity of an RPC interface = **GUID (IID) + version**. The endpoint is *where
to connect*. Two separate axes; multiple interfaces can be registered on the same
endpoint.

```
Transport      : ncalrpc:[protected_storage]   (same machine, ALPC)
                 ncacn_np:[\PIPE\protected_storage] (network; disabled in this analysis)
Interface IID  : {11220835-5B26-4D94-AE86-C3E475A809DE} v1.0
Transfer syntax: {8A885D04-1CEB-11C9-9FE8-08002B104860} = NDR 2.0
Procedure count: 3  ->  opnum 0 = protect, 1 = unprotect, 2 = UpdateProtectedState
```

### 3.3 NDR — how the data is held in the packet

Neither the client proxy-info nor the server interface struct holds the byte layout
of the parameters *directly*; both point, via a `MIDL_STUB_DESC`, to two **format
strings**:

- **ProcFormatString** — the parameter list of each procedure (in/out direction,
  stack offset, type offset).
- **TypeFormatString** — the actual data shapes (struct, pointer, conformant array,
  size). The wire layout of DATA_BLOB is here.

Compiled from the same IDL, they are identical on both sides; the client marshals
with them, the server unmarshals. opnum 0 parameters (from ProcFormatString):

```
p1  handle_t   binding       (does not go on the wire; local ALPC handle)
p2  [in]  DATA_BLOB  pDataIn        (transit-wrapped data)
p3  [in]  wchar_t*   szDataDescr    (FC_C_WSTRING)
p5  [in]  DATA_BLOB  pOptionalEntropy (unique ptr -> may be NULL)
p6  [in]  <ptr>      pReserved/prompt
p7  [in]  long       dwFlags        (FC_LONG)
p8  [out] DATA_BLOB  pDataOut       (the produced DPAPI blob)
```

NDR serialization of DATA_BLOB (FC codes: FC_STRUCT 0x15, FC_UP 0x12,
FC_CARRAY 0x1b, FC_LONG 0x08):

```
DATA_BLOB:
   ├─ cbData : 4 bytes (FC_LONG)
   └─ pbData : unique pointer (FC_UP)
        if != NULL, referent:
           ├─ conformance count : 4 bytes (= cbData)
           └─ <cbData> bytes of data
```

Entropy is processed in the **service**, not in the caller's process. Unmarshal/marshal
buffers are allocated and freed via the stub descriptor's `pfnAllocate`/`pfnFree`
(dpapisrv: FUN_0046f0 / FUN_0168e0).

### 3.4 Server dispatch (dpapisrv.dll)

`RpcServerRegisterIf3` only **registers** the ready-made interface struct with rpcrt4;
the opnum→function mapping is produced at MIDL compile time. Runtime chain:

```
client -> rpcrt4 -> ProtectCallback (gatekeeper, may ACCESS_DENIED)
       -> RPC_DISPATCH_TABLE[*] = NdrServerCall2
       -> read opnum -> MIDL_SERVER_INFO.DispatchTable[opnum]
            [0] s_SSCryptProtectData    (0x75b0)
            [1] s_SSCryptUnprotectData  (0x7d40)
            [2] s_SSCryptUpdateProtectedState (0x26d50)
       -> unmarshal [in] -> server routine -> SPCryptProtect/SPCryptUnprotect
```

`NdrServerCall2` (rpcrt4) is the mirror of `NdrClientCall3`: it unmarshals with the
same format strings, the work finishes, then marshals `[out]` + the return and sends
the ALPC reply. (Full struct walk and addresses in §13.)

`ProtectCallback` (the per-call gatekeeper) has a single criterion: the **transport
channel**. `RpcBindingToStringBindingW` -> `RpcStringBindingParseW` extracts the
caller's protseq, and `CompareStringW(protseq, "ncalrpc")` returns `0` (allow) if
equal, else `5` (`ERROR_ACCESS_DENIED`). So even though the service registers both
`ncalrpc` and `ncacn_np`, IF#1 accepts **only local ALPC callers**; named-pipe (remote)
requests are dropped in this callback. Two channels, one door.

---

## 4. RtlEncryptMemory — Transit Protection (user ↔ kernel)

The layer `CryptProtectDataNoUI` wraps the data in before putting it in the RPC
packet. It goes down to the kernel via IOCTL (it does not RPC to lsass); DeviceType
`0x39`, METHOD_OUT_DIRECT (in-place via MDL, no copy). OptionFlags (scope) + direction
map to a control code:

| Scope | OptionFlags | Encrypt IOCTL | Decrypt IOCTL |
|---|---|---|---|
| SAME_PROCESS  | 0 | `0x39000e` | `0x390012` |
| CROSS_PROCESS | 1 | `0x390016` | `0x39001a` |
| SAME_LOGON    | 2 | `0x39001e` | `0x390022` |
| SYSTEM        | 4 | `0x39007a` | `0x39007e` |

There is a `0x4` difference between encrypt/decrypt codes. An invalid code/misalignment
-> `STATUS_INVALID_PARAMETER` (`0xC000000D`). The DPAPI client uses **SAME_LOGON (2)**.
On the kernel side the request reaches the actual crypto function `CngEncryptMemoryEx`.

---

## 4.5. ksecdd → cng Handover (the extension mechanism)

`\Device\KSecDD` is owned by **ksecdd**; the crypto is in **cng**. ksecdd does not
call cng directly (does not import it) — cng binds to ksecdd as an *extension* at load
time.

**Binding (`ksecdd!LoadCngExtension`, in DriverEntry):** ksecdd opens `\Device\CNG`
(`IoGetDeviceObjectPointer`) and issues three IOCTLs to cng to **pull** its function
pointers (`IoBuildDeviceIoControlRequest` + `IofCallDriver`):

```
0x390040  IOCTL_KSEC_GET_BCRYPT_EXTENSION         -> gKsecpBCryptExtension
0x390044  IOCTL_KSEC_GET_SSL_EXTENSION            -> gKsecpSslExtension
0x390048  IOCTL_KSEC_GET_DEVICECONTROL_EXTENSION  -> gKsecpDeviceControlExtension
```

Each returns an 8-byte pointer from cng's own dispatch. The device-control pointer is
**`CngDeviceControl`** in cng's `.rdata` extension table (confirmed as a VA at
`cng+0xa13a8`).

**Runtime (`ksecdd!KsecDispatch`):** when a crypto IOCTL arrives at `\Device\KSecDD`,
ksecdd forwards the request that does not match its own codes in the **default** branch
with an indirect, CFG-protected call (`_guard_dispatch_icall`):

```
(*gKsecpDeviceControlExtension)(inBuf, inLen, outBuf, &byteCount, IoControlCode, RequestorMode)
   -> cng!CngDeviceControl  -> resolve (scope, dir)  -> CngEncryptMemoryEx(outBuf, byteCount, dir, scope)
```

In short: ksecdd is the device's **door**, cng is the **tenant**; no static bind, cng
hands over the pointer via IOCTL when loaded, and ksecdd passes the device-control
IOCTLs it does not recognize to it.

---

## 5. Root Material (`CngEncryptMemoryInitialize`, cng+0x5d7a4)

Generation is **lazy**: done once on the first `CngEncryptMemoryEx` call while the
`InitializedMemory` flag is `0` (protected by `CngEncryptMemMutex` = `cng+0xbf118`,
`ExAcquireFastMutex`). `SystemPrng` produces **three independent raw randoms** (24B,
16B, 16B) and distributes them:

```
SystemPrng #1 (24B) ─┬─ SymCrypt3DesExpandKey        -> g_DES3Key (CROSS-3DES schedule)
                     ├─ SymCryptSha1Init(g_ShaHash)
                     └─ SymCryptSha1Append(g_ShaHash, #1, 24)   -> g_ShaHash buffer = raw #1
SystemPrng #2 (16B) ─┬─ SymCryptAesExpandKeyInternal  -> g_AESKey (CROSS-AES schedule)
                     ├─ SymCryptSha1Init(g_AESHash)
                     └─ SymCryptSha1Append(g_AESHash, #2, 16)   -> g_AESHash buffer = raw #2
SystemPrng #3 (16B) ──── movdqu -> RandomSalt                   (raw, CBC IV)
InitializedMemory <- 1   (xchg);  the three raw copies on the stack are zeroed at the end with rep stosb
```

| SystemPrng | Size | Raw read address | Role |
|---|---|---|---|
| #1 | 24B | `g_ShaHash`+0x20 = `cng+0xbf240` | SHA derivation root **and** CROSS-3DES key |
| #2 | 16B | `g_AESHash`+0x20 = `cng+0xbf1b0` | CROSS-AES key (`g_AESKey` raw form) |
| #3 | 16B | `RandomSalt` = `cng+0xbf210` | CBC IV (AES: full 16B, 3DES: first 8B) |

**Note — `g_AESHash` is dead:** it is fed into the SHA-1 state but *never used* in the
derivation path; it only keeps a readable copy of random #2. The only SHA state used in
derivation is `g_ShaHash`.

The randoms are **volatile**; regenerated every boot (transit-only).

---

## 6. CngEncryptMemoryEx (cng+0x1f430) — End to End

Signature (observed): `CngEncryptMemoryEx(rcx=buf, edx=size, r8d=dir, r9d=scope)`
— `dir` 0=decrypt, !=0=encrypt; `scope` = OptionFlags.

### 6.1 Algorithm selection — block alignment and the `edi` flag
```
test size, 0xf
  == 0  -> edi = 1   ->  AES-128     (size % 16 == 0)
  != 0  -> test size, 7
            == 0 -> edi STAYS 0 ->  3DES  (size % 8 == 0, %16 != 0)
            != 0 -> STATUS_INVALID_PARAMETER (0xC000000D)
```
`edi == 1 <=> AES`, `edi == 0 <=> 3DES`.

### 6.2 Lazy initialization
`cmp InitializedMemory, 0 ; je -> CngEncryptMemoryInitialize` (§5).

### 6.3 Scope -> identity
```
scope 0  SAME_PROCESS  -> ZwQueryInformationProcess(0x24=ProcessCookie) + PsGetProcessCreateTimeQuadPart
                         identity = cookie(4B) ‖ time(8B)
scope 2  SAME_LOGON  ┐
scope 4  SYSTEM      ┘  SeCaptureSubjectContext -> SeQueryAuthenticationIdToken -> caller LUID
                         ├─ SAME_LOGON -> identity = caller LUID (8B)
                         └─ SYSTEM     -> identity = constant 0x3e2 (8B);
                                         decrypt (dir==0) and caller LUID != 0x3e7 -> ACCESS_DENIED
scope 1  CROSS_PROCESS -> NO identity
```

### 6.4 Key derivation
```
AES-128, non-CROSS : AES_key = SHA1(g_ShaHash_root(24B) ‖ identity)[:16]
AES-128, CROSS     : AES_key = g_AESKey (random #2)
3DES, non-CROSS    : d1 = SHA1(root ‖ "aaa" ‖ id); d2 = SHA1(root ‖ "bbb" ‖ id)
                     DES3_key(24B) = d1[:20] ‖ d2[:4]
3DES, CROSS        : DES3_key = g_DES3Key (random #1)
```

### 6.5 Cipher (CBC)
```
AES  : AES-128-CBC, IV = RandomSalt (16B); dir==0 decrypt / dir!=0 encrypt
3DES : 3DES-CBC (EDE), IV = RandomSalt[:8]; CBC chaining done by hand
```

---

## 7. Security Model

- **DPAPI master key**: password-derived, in lsass, persistent. "Who can decrypt" =
  same user + same password. For offline, the password is required.
- **RtlEncryptMemory root material**: random, in the kernel, volatile. "Who can
  decrypt" = a match of the scope identity (cookie/LUID/constant). The real secrecy
  rests on a single kernel secret (the root) — reading it already requires full
  compromise.
- **Math**: same root + same scope identity -> same key. When the boot changes the
  root changes -> no old transit data can be decrypted.
- **CROSS_PROCESS** is the exception: no identity, a single machine-wide constant key.
- **lsass boundary** (§13): **dpapisrv decrypts the master key itself** (from the
  on-disk file, with the pre-key — `DecryptMasterKeyToMemoryEx`). What comes from
  lsasrv is not the master key but the **credential** (the password hash): dpapisrv
  obtains pwdhash/derived-credential from lsasrv via `g_pDPAPILsasrvIfTable` with
  `RetrieveCurrentDerivedCredential` / `LsaIDeriveCredentialKey`, and derives the
  pre-key from it. The plaintext password reaches nowhere; the credential lives in
  lsasrv, the decrypted master key lives (temporarily) in dpapisrv memory. All within
  a single process (lsass).

---

## 8. NTSTATUS / Win32 Codes

```
0x00000000  STATUS_SUCCESS
0xC000000D  STATUS_INVALID_PARAMETER   (invalid mode / alignment)
0xC0000022  STATUS_ACCESS_DENIED       (unauthorized access to SYSTEM decrypt)
0xC0000001  STATUS_UNSUCCESSFUL        (SystemPrng failed — init)
0xC00000A5  STATUS_BAD_IMPERSONATION_LEVEL

Client (dpapi.dll) Win32:
0x00000057  ERROR_INVALID_PARAMETER    (input validation)
0x0000000E  ERROR_OUTOFMEMORY          (LocalAlloc failed)
0x00001770  (6000) transit encrypt (SystemFunction040) failed
0x00001771  (6001) transit decrypt (SystemFunction041) failed
0x0000000D  ERROR_INVALID_DATA         (unprotect: invalid padding)
0x00091012  tolerated state (unprotect together with flags & 0x40)
```

---

## 9. Address + Symbol Table — cng.sys (26100.1150, base 0x1c0000000)

```
CngEncryptMemoryEx            cng+0x1f430   the actual crypto: alignment->scope->identity->derive->CBC
CngEncryptMemoryInitialize    cng+0x5d7a4   lazy root generation (SystemPrng x3, mutex)
GenerateAESKey                cng+0x16cf8   identity -> SHA1 -> AES-128 schedule
GenerateKey                   cng+0x156cc   identity -> "aaa"/"bbb" double-SHA1 -> 3DES schedule
SymCryptSha1Init/Append/Result cng+0x16cd0 / 0x15860 / 0x15960
SymCryptAesExpandKeyInternal  cng+0x17850
SymCrypt3DesExpandKey         cng+0x15000
SymCryptAesCbcEncrypt         cng+0x1ed80
SymCryptAesCbcDecrypt(Xmm)    cng+0x1eed0   / Asm cng+0x4e8a0
SymCrypt3DesEncrypt/Decrypt   cng+0x20c10 / 0x1fa10
SystemPrng                    cng+0x184d0
SymCryptWipeAsm               cng+0x4e210
```

Global variables (.data):
```
cng+0xbf114  InitializedMemory     cng+0xbf118  CngEncryptMemMutex
cng+0xbf1b0  g_AESHash+0x20 = raw random #2 (16B, CROSS-AES)
cng+0xbf210  RandomSalt = raw random #3 (CBC IV)
cng+0xbf240  g_ShaHash+0x20 = raw random #1 (24B, sha_root)
cng+0xbf2a0  g_AESKey      cng+0xbf490  g_DES3Key
cng+0xa7000  "aaa"         cng+0xa5c10  "bbb"
```

---

## 10. Verification (live KDNET, 26100.1150)

Values read from the kernel in this boot session:

```
InitializedMemory (bf114)      = 01
SHA root   (bf240, L18)        = 77 5f c4 58 48 23 dc ae 04 3d ca 33 85 39 00 a4 04 de 03 c2 e9 6a f6 fb
RandomSalt (bf210, L10)        = 0f 91 d1 c3 cf 88 ea d4 ec 85 69 38 f6 d6 94 a6
g_AESKey[0](bf2a0, L10)        = 7b c4 ed 1b dd 86 ab 66 97 62 14 34 bd 6f 91 3f
```

Live verification (SAME_LOGON, AES, caller LUID = 0x441D4, plaintext = 00..0F):
```
identity = d4 41 04 00 00 00 00 00
AES key = SHA1(root ‖ id)[:16] = 79 b9 1d 16 b1 e9 f0 77 f6 ca e6 c8 11 80 98 bf
real ciphertext  = d4 46 c8 92 55 30 3b 82 7c b0 3c 55 81 0f 62 46
model ciphertext = d4 46 c8 92 55 30 3b 82 7c b0 3c 55 81 0f 62 46   ✓
```

Live verification #2 (SAME_LOGON, 3DES, LUID = 0x441D4, plaintext = 00..17):
```
3DES key = SHA1(root‖"aaa"‖id)[:20] ‖ SHA1(root‖"bbb"‖id)[:4]
         = d9 3b 2a e8 54 a6 6a 2f 99 4a d4 3f b1 ff 8b 92 ee ff 7f 25 0e 0a e3 da
real/model ciphertext = 48 17 ce fb 91 ab 4d 13 bb 21 2a 56 3c 34 23 62 6c 07 fa 39 c1 e6 99 ad   ✓
```

`cng_encdec_memory.py` reproduces both paths byte-for-byte with the real
`CngEncryptMemoryEx` output. The model is complete.

---

## 11. Diagrams

- `rtl_encrypt_flow.png` / `rtl_decrypt_flow.png` — transit crypto (cng), source
  `rtl_encrypt_flow.html` / `rtl_decrypt_flow.html`.
- `cryptprotect_chain.png` — the full `CryptProtectData` chain (app -> dpapi.dll ->
  transit -> RPC -> dpapisrv/lsass -> master key -> return), source
  `cryptprotect_chain.html`. Transit (RtlEncryptMemory) detailed in a separate diagram.
- `cryptunprotect_chain.png` — the full `CryptUnprotectData` chain, source
  `cryptunprotect_chain.html`. Transit (RtlDecryptMemory) detailed in a separate diagram.
- `masterkey_flow.png` — acquiring the master key (from password to master key:
  pre-key derivation -> GetMasterKey multi-identity/CREDHIST -> DecryptMasterKeyToMemoryEx
  XOR-feedback PBKDF2; protect uses GetPreferred, unprotect uses GetSpecified), source
  `masterkey_flow.html`. The visual for §15.

---

## 12. Scope × Algorithm — Live Verification Status (26100.1150, this boot)

| Scope | Identity | AES key | 3DES key | Live confirmation |
|---|---|---|---|---|
| SAME_PROCESS  | cookie(4)‖time(8) | SHA1(root‖id)[:16] | SHA1(root‖"aaa"‖id)[:20]‖SHA1(root‖"bbb"‖id)[:4] | model produces |
| SAME_LOGON    | LUID(8) | SHA1(root‖id)[:16] | same pattern | **AES ✓ · 3DES ✓** |
| SYSTEM        | 0x3e2(8) | SHA1(root‖id)[:16] | same pattern | model produces |
| CROSS_PROCESS | none | g_AESKey = cross_key16 | g_DES3Key = root24 | **AES ✓ · 3DES ✓** |

---

## 13. The lsass Side: dpapisrv.dll

### 13.1 Identity and loading

`dpapisrv.dll` is not a standalone program; it is an **LSA extension loaded inside
lsass.exe**. There is no separate process; its code runs in the lsass process. It has
only **two exports**:

```
ord 1  InitializeLsaExtension   0x2b820   the load gate lsass calls
ord 2  QueryLsaInterface        0x2b880   hands the function table to lsass
```

At boot, lsass loads dpapisrv from the extension list in the registry and calls
`InitializeLsaExtension(stage=1)`.

### 13.2 The two interface tables — their directions

There are two tables, in opposite directions; the name similarity is misleading:

| Table | Address | Type | Filled by | Called by | Direction |
|---|---|---|---|---|---|
| `g_pDPAPILsasrvIfTable` | 0x502a0 | `_LSA_IF_LSASRV_FUNCTION_TABLE*` | dpapisrv (at init) | **dpapisrv** | dpapisrv -> lsass (up) |
| `g_pDPAPIIfTable` | 0x4f000 | `_LSA_IF_DPAPI_FUNCTION_TABLE` | static (at compile) | **lsass** | lsass -> dpapisrv (down) |

**Evidence (xref):**
- `g_pDPAPIIfTable` is referenced in **one** place inside dpapisrv: `QueryLsaInterface`
  (0x2b88a), only to return its address to lsass. dpapisrv never calls it ->
  outward-facing; **lsass calls it.**
- `g_pDPAPILsasrvIfTable` in **23** places: 1 filler (`InitializeLsaExtension`
  @0x2b82d), 22 users — all privileged work: `GetPreferredMasterKey`,
  `RestoreMasterKey`, `GetSpecifiedMasterKey`, `RetrieveCurrentDerivedCredential`,
  `VerifyCredentials`, `PRCreateLocalToken`… So dpapisrv has lsass (lsasrv) do work
  like master key / token through this table.

The first entries of `g_pDPAPIIfTable` are the surface lsass calls DPAPI through:
```
[0] DPAPICryptProtectData   [1] DPAPICryptUnprotectData
[2] DPAPICryptProtectDataEx [3] DPAPICryptUnprotectDataEx
[4] DPAPINotifyLogonTerminated   [5] DPAPINotifyCredentialKeyChange
[6] LsaIfSynchronizeMasterKeys   [7] LsaIfIsDcTargetForRecovery
[8] LsaIfGetCurrentCredentialKeyId
```

### 13.3 Setup — `DPAPIInitialize` (0x2b5b4), step by step

```
InitializeLsaExtension(1)
  ├─ LsaGetInterface(0x3e9, &g_pDPAPILsasrvIfTable)  -> FILL the up-table
  └─ DPAPIInitialize():
       1  ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL) -> port access SD
            D:(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)(A;;GA;;;BA)(A;;GA;;;OW)(A;;GR;;;AC)(A;;GR;;;S-1-15-3-…)
       2  AllocateLocallyUniqueId
       3  FMyProviderCacheInit
       4  InitializeGlobals   -> RegCreateKeyExW(…\Cryptography\Protect) + CreateEventW + critsec
       5  InitializeKeyManagement -> critsec
       6  RpcServerUseProtseqEpW("ncalrpc",  "protected_storage",       SD)   <- local ALPC
       7  RpcServerUseProtseqEpW("ncacn_np", "\PIPE\protected_storage", SD)   <- named pipe
       8  RpcServerRegisterIf3(&IF#1 {11220835}, …, IfCallback=ProtectCallback, SD)
       9  RpcServerRegisterIf3(&IF#2 {5CBE92CB}, …)
      10  SIDKeyEnableLRpcInterface()   -> the SID-key interface's own registration (separate SD)
      11  IsDomainController()           -> late-bound (GetModuleHandleW/GetProcAddress)
      12  StartBackupKeyServer()         -> QueueUserWorkItem (domain backup key worker)
      13  [0x50298] = 1                  -> "setup done" flag
```

`g_pDPAPIIfTable` export: `QueryLsaInterface(0x3ea, out)` -> `*out = &g_pDPAPIIfTable`.

When a request lands in `DPAPICryptProtectDataEx`, the first check is
`if (DAT_180050298 == 0) return 0x54f;` — the flag from step 13; requests are not
processed before setup finishes.

### 13.4 Dispatch — from RegisterIf3 to the functions

The first argument of `RegisterIf3` (rcx) is the interface struct; the mapping is in
the static MIDL tables inside it (since MgrEpv = NULL, the interface's own table is
used):

```
RPC_SERVER_INTERFACE @0x418d0  (IF#1 {11220835} v1.0, TransferSyntax {8A885D04}=NDR2.0)
   +0x30 DispatchTable   -> RPC_DISPATCH_TABLE @0x41c70 (Count=3, all -> NdrServerCall2)
   +0x50 InterpreterInfo -> MIDL_SERVER_INFO @0x41ca0
                             +0x00 pStubDesc @0x41160 (+0x40 pFormatTypes=TypeFmt @0x44122)
                             +0x08 DispatchTable @0x411f8:
                                   [0] s_SSCryptProtectData          0x75b0
                                   [1] s_SSCryptUnprotectData        0x7d40
                                   [2] s_SSCryptUpdateProtectedState 0x26d50
                             +0x10 ProcString @0x441e2
                             +0x18 FmtStringOffset @0x441d4  (opnum offsets: 0, 102, 204)
```

`DPAPICryptProtectData` (0x4790) and `s_SSCryptProtectData` (0x75b0) are two separate
entries: the first is the in-LSA gate triggered by lsass via `g_pDPAPIIfTable`, the
second is the gate triggered by RPC. Both meet in `SPCryptProtect`. Neither is called
in code with `call <name>`; they are triggered by opnum/index from the tables.

### 13.5 The crypto core — `SPCryptProtect` (confirmed by decompile)

`SPCryptProtect` multiplexes several jobs by flag; the normal encryption path is below.
`dwFlags & 8` -> master key **synchronization** (returns early before encrypting),
`dwFlags & 0x80000000` -> `DpapiUpdateLsaSecret` (returns early).

**Argument source** (from the `DPAPICryptProtectDataEx` call):

| SPCryptProtect param | Source |
|---|---|
| ctx | server — `CPSCreateServerContext` (RPC binding, caller token) |
| pbOut/pcbOut | output -> pDataOut |
| pbIn/cbIn | **CryptProtectData.pDataIn** (transit-wrapped on the wire) |
| szDataDescr | **CryptProtectData.szDataDescr** |
| pEntropy/cb | **CryptProtectData.pOptionalEntropy** |
| pPromptStruct | CryptProtectData.pPromptStruct (usually NULL in NoUI) |
| dwFlags | **CryptProtectData.dwFlags** + internal bits |
| entropy2 | **external** — no counterpart in CryptProtectData; NULL on the normal path |

**Key derivation chain** (verified — `dpapi_protect.py`):
```
root       = SHA1(masterKey)                       # FMyPrimitiveSHA (if >20B; only size normalization)
hmac       = HMAC(key=root, hash=hashAlg, msg = salt ‖ entropy ‖ entropy2)
cipherKey  = CryptDeriveKey(hmac, keyLen)          # FMyDeriveBCryptKey -> BCryptDeriveKeyCapi
ciphertext = CBC_enc(cipherKey, IV = 0, plaintext + block-pad)   # BCryptEncrypt (pbIV=NULL, pad=1)
MAC        = HMAC(root, hash=hashAlg, msg = macSalt ‖ entropy ‖ entropy2 ‖ blobBody)
```
- The persistent crypto is done with **BCrypt** (not the kernel's SymCrypt).
- HMAC key = `SHA1(masterKey)`; hash = the chosen alg (modern: SHA-512). Salt -> cipher
  key, macSalt -> MAC. For AES-256/SHA-512, salt/macSalt are 32B, otherwise 16B.
- If `hashAlg == SHA1` the HMAC is set up via legacy `INCORRECT_FMyPrimitiveCryptHMAC`,
  otherwise via `BCryptCreateHash(HMAC)` — **both are HMAC**, just an implementation
  difference. The MAC is always produced and always verified on every unprotect (not
  optional).

**Transit opening is CONDITIONAL:**
```
if (dwFlags & 0x60000000)   -> input is already plain -> SKIP transit opening   (in-LSA path, |0x40000000)
else                        -> RpcImpersonateClient -> SystemFunction041(pbIn,cbIn,2) -> RevertToSelf
                              strip padding (last byte = length; if not 0<pad<=8 then 0xD)
```
The RPC path from dpapi.dll does not set these bits -> transit is opened; moreover,
since the transit key is bound to the caller's LUID, the opening is done **while
impersonating the caller**.

**Full flow:**
```
s_SSCryptProtectData (0x75b0, RPC)  |  DPAPICryptProtectData 0x4790 -> …Ex 0x4c90 (in-LSA)
   -> CPSCreateServerContext (0x8000)
   -> SPCryptProtect (0x5ed0):
        ├─ GetDefaultAlgInfo (0xc400)                -> alg IDs (cipher/hash)
        ├─ GetBCryptProviderHandle x3                -> cipher / hash / HMAC provider
        ├─ GetPreferredMasterKey (0xcf80)            -> MASTER KEY (credential from lsasrv via g_pDPAPILsasrvIfTable)
        ├─ FMyPrimitiveSHA (0x5830)                  -> root = SHA1(masterKey)
        ├─ BCryptGenRandom x2                        -> salt, macSalt
        ├─ [conditional] RpcImpersonateClient -> SystemFunction041 -> RevertToSelf  (OPEN transit)
        ├─ HMAC_root(salt‖ent‖ent2) -> FMyDeriveBCryptKey (0xc500) -> cipherKey
        ├─ build blob (ver‖mkGUID‖flags‖descr‖alg‖salt‖…‖macSalt) + BCryptEncrypt (IV=0)
        ├─ HMAC_root(macSalt‖ent‖ent2‖blobBody) -> BCryptFinishHash -> MAC
        ├─ RpcServerInqCallAttributesW+OpenProcess+NtQueryInformationProcess -> CPSAudit
        └─ wipe the raw master key (LocalFree), destroy key/hash handles
   -> +0x14 header: version(1) ‖ provider GUID {DF9D8CD0-1501-11D1-8C7A-00C04FC297EB}  (…Ex adds it)
   -> CPSDeleteServerContext (0x7830)

SPCryptUnprotect (0x9e90) — full flow (decompile, IDENTICAL to dpapi_protect.unprotect):
   -> GetDefaultAlgInfo
   -> GetSpecifiedMasterKey (0x13950)    <- the mkGUID INSIDE the blob (the difference from protect's GetPreferred!)
   -> FMyPrimitiveSHA -> root = SHA1(masterKey)
   -> VERIFY MAC: INCORRECT_FMyPrimitiveCryptHMAC = HMAC_root(macSalt‖ent‖ent2‖blobBody)
        -> BCryptHashData/FinishHash -> memcmp(stored MAC)   <- on mismatch returns without decrypting
   -> cipherKey: HMAC_root(salt‖ent‖ent2) -> FMyDeriveBCryptKey -> CryptDeriveKey
   -> BCryptDecrypt (IV=0) -> strip block-pad -> plaintext
   -> [conditional] RpcImpersonateClient -> SystemFunction040 (=RtlEncryptMemory) -> RevertToSelf
        (wraps the plaintext in transit BEFORE returning it to the caller, SAME_LOGON)
   -> RpcServerInqCallAttributesW+OpenProcess+NtQueryInformationProcess -> CPSAudit
```

**The single cryptographic difference between protect and unprotect:** protect uses
`GetPreferredMasterKey` (encrypts with the active key), unprotect uses
`GetSpecifiedMasterKey` (decrypts with the key named by the blob's own GUID). The rest
(root=SHA1(mk), HMAC MAC, CryptDeriveKey, CBC IV=0) is symmetric — the
`dpapi_protect.unprotect`/`protect` model is verified byte-for-byte against this.

The master key is not held by dpapisrv in the sense of coming from lsasrv:
`GetPreferredMasterKey` makes an in-process indirect call to lsasrv via the up-table —
but what it obtains is the **credential** (pwdhash), not the master key; dpapisrv
decrypts the master key itself from the on-disk file. The raw master key lives only
until its SHA1 is taken, then it is wiped. This is the binary counterpart of the
security boundary in §7.

### 13.6 All RPC interfaces registered in the service (four — confirmed)

All on the same `protected_storage` endpoint (ncalrpc); GUIDs and dispatch tables read
from the binary:

```
IF#1 {11220835-5B26-4D94-AE86-C3E475A809DE} v1.0   @struct 0x418d0   <- OUR PATH
       data protection:
       [0] s_SSCryptProtectData   [1] s_SSCryptUnprotectData   [2] s_SSCryptUpdateProtectedState

IF#2 {5CBE92CB-F4BE-45C9-9FC9-33E73E557B20} v1.0   @struct 0x414f0
       recovery agent:
       [0] s_SSRecoverQueryStatus  [1] s_SSRecoverImportRecoveryKey  [2] s_SSRecoverPassword
       (recovery-key import + password recovery — enterprise DPAPI recovery)

SID-key {7F1317A8-4DEA-4FA2-A551-DF5516FF8879} v1.0  @struct 0x424f0
       ISIDKeyProtect — registered SEPARATELY via SIDKeyEnableLRpcInterface (its own SD):
       [0] s_LRpcSIDKeyProtect     [1] s_LRpcSIDKeyUnprotect
       (SID-bound key protection; group/service scenarios)

MS-BKRP {3DDE7C30-165D-11D1-AB8F-00805F14DB40} v1.0   (dpapisrv is the CLIENT here)
       NdrClientCall3 @0x28db4, ProxyInfo @0x420f0; via StartBackupKeyServer it goes to
       the DC's backup key service (domain master key backup/recovery).
```

The main axis of our analysis is **IF#1**; IF#2 and SID-key are different APIs on the
same port, and MS-BKRP is the channel where dpapisrv talks to the DC as a client.

### 13.7 Ghidra navigation recipe (finding the IF#1 functions)

```
1. Imports -> RPCRT4 -> RpcServerRegisterIf3 -> References -> call @0x18002b717
2. Above the call: lea rcx,[0x1800418d0]   -> IF#1 struct (3rd arg MgrEpv = NULL)
3. 0x1800418d0 +0x04 GUID = {11220835…}  (confirm)
4. +0x50 -> MIDL_SERVER_INFO @0x180041ca0
5. +0x08 -> DispatchTable @0x1800411f8
6. [0]=0x1800075b0 s_SSCryptProtectData, [1]=0x180007d40, [2]=0x180026d50
7. bound: RPC_DISPATCH_TABLE @0x180041c70, Count=3
```

### 13.8 Master key backup (OUTSIDE the chain)

In a domain, each user's DPAPI master key is also encrypted — besides the
password-derived key — with a **domain backup key** (an RSA pair held on the DCs), so
the master key can be recovered when the password is reset. On a standalone machine a
local backup key is used. lsass talks to the DC about this over **MS-BKRP**
({3DDE7C30-…}) (`StartBackupKeyServer`, `GeneratePublicKeyCert`, the NCrypt KSP path).

This is **not part of the per-blob protect/unprotect crypto.** The backup key operates
in the master keys' life cycle (creation/recovery/sync) — i.e. *above*
`GetPreferredMasterKey`. Inside `SPCryptProtect`, backup/sync happens only in the
`dwFlags & 8` branch and returns early without encrypting the data. Someone who captures
the decrypted master key in memory and decrypts the blob is below this point; outside
the recovery scenario it has no place in this analysis chain.

### 13.9 Verified model

`dpapi_protect.py` implements the chain in §13.5 and has been verified live: with the
**raw master key** (the single secret) captured at the return of
`dpapisrv!GetPreferredMasterKey` in a kernel debugger, a real `CryptProtectData` blob
is decrypted by `unprotect()` (`mac_ok=True`, plaintext matches). The rest of the blob
(salt, macSalt, alg IDs, ciphertext, MAC) is parsed from inside the blob; if you capture
salt/macSalt from the `BCryptGenRandom` calls, `protect()` reproduces the blob
byte-for-byte.

---

## 14. Address + Symbol Table — dpapisrv.dll (base 0x180000000)

```
InitializeLsaExtension        0x2b820   LSA extension load gate (export)
QueryLsaInterface             0x2b880   hands g_pDPAPIIfTable to lsass (export)
DPAPIInitialize               0x2b5b4   RPC registration + service setup
DPAPIShutdown                 0x2b8a4   unregistration
ProtectCallback               0x181e0   RegisterIf3 per-call security gatekeeper
InitializeGlobals             0x387d8   registry + event + critsec
InitializeKeyManagement       0x2fca8
StartBackupKeyServer          0x37708   QueueUserWorkItem (domain backup)
SIDKeyEnableLRpcInterface     0x3d23c   SID-key interface registration

DPAPICryptProtectData         0x4790    in-LSA protect entry (g_pDPAPIIfTable[0])
DPAPICryptUnprotectData       0x7540    in-LSA unprotect entry
DPAPICryptProtectDataEx       0x4c90    protect manager (+flags)
DPAPICryptUnprotectDataEx     0x78c0    unprotect manager
s_SSCryptProtectData          0x75b0    RPC opnum 0 stub
s_SSCryptUnprotectData        0x7d40    RPC opnum 1 stub
s_SSCryptUpdateProtectedState 0x26d50   RPC opnum 2 stub
SPCryptProtect                0x5ed0    the actual protect crypto core
SPCryptUnprotect              0x9e90    the actual unprotect crypto core
CPSCreateServerContext        0x8000    build request context
CPSDeleteServerContext        0x7830    tear down context
GetPreferredMasterKey         0xcf80    get the active master key (dpapisrv; credential from lsasrv)
GetSpecifiedMasterKey         0x13ed0
FMyDeriveBCryptKey            0xc500    derive the session key
GetDefaultAlgInfo             0xc400    select the algorithm
FMyPrimitiveCryptHMAC         0xcac0    HMAC
FMyPrimitiveSHA               0x5830
GetBCryptProviderHandle       0x5b20
NdrServerCall2 (thunk)        0x1f820   generic RPC dispatcher -> rpcrt4
stub pfnAllocate / pfnFree    0x46f0 / 0x168e0

Globals (.data):
g_pDPAPIIfTable               0x4f000   lsass->dpapisrv (down) function table
g_pDPAPILsasrvIfTable         0x502a0   dpapisrv->lsass (up) pointer
blob header provider GUID     0x4f528   {DF9D8CD0-1501-11D1-8C7A-00C04FC297EB}
RPC_SERVER_INTERFACE IF#1     0x418d0   {11220835…}
RPC_SERVER_INTERFACE IF#2     0x414f0   {5CBE92CB…}
MIDL_SERVER_INFO (IF#1)       0x41ca0   +0x08 DispatchTable @0x411f8
```

---

## 15. Acquiring the Master Key — the `GetPreferredMasterKey` Chain

`GetPreferredMasterKey` from §13.5 is the call that obtains the single secret of the
persistent DPAPI crypto — the 64-byte master key. The master key never returns to the
caller; it is derived and used inside lsass. This section gives the full chain of that
derivation (line by line from the `dpapisrv.dll` decompile).

Note: there are two separate "encryptions", not to be confused.

| Layer | What is encrypted | Key | This section |
|---|---|---|---|
| **Data blob** (§13.5, `dpapi_protect.py`) | the application's data | session key derived from the master key | no |
| **Master key file** (§15, `masterkey.py`) | the master key **itself** | **pre-key (DP_KEK)** derived from the password | yes |

### 15.1 pre-key (DP_KEK) — the key that unlocks the master key file

The master key is stored **encrypted** on disk
(`%APPDATA%\Microsoft\Protect\<SID>\<GUID>`); the key that unlocks it is derived from
the password in two steps (`ComputeMasterKeyUserEncryptionKey` -> `DeriveWithHMAC_SHA1`):

```
credential_key = SHA1( password · UTF-16LE )                    # 20 bytes; MSV1_0 holds it from logon
pre_key        = HMAC-SHA1( credential_key, (SID + "\0")·UTF-16LE )  # DP_KEK
```

dpapisrv does not hash the password — it requests the credential key (`LsaIDeriveCredentialKey`).
That key is the 20-byte value MSV1_0's `MspGetCredentialKeyWorker` copies out of the primary
credential (type 2 → cred+0x32, type 3 → cred+0x66), placed there at logon by NtlmShared's
`MsvpPutClearOwfsInPrimaryCredential`. It is the password's **SHA-1** (20 bytes), **not** the 16-byte
NT OWF/MD4 — so there is no NTLM/MD4 variant for the DPAPI credential key on current Windows. The
full acquisition path is its own diagram (credkey_flow). pre-key is **not** applied to the master
key directly; it enters as the *password* of the PBKDF2 below. `DeriveWithHMAC_SHA1` builds HMAC-SHA1
by hand with ipad/opad (two SHA-1 rounds).

The DP_KEK has **more than one source** — the password form above is only the user case. Machine
(CRYPTPROTECT_LOCAL_MACHINE), Local-System and the service accounts have no password; their DP_KEK
is a 20-byte half of the **DPAPI_SYSTEM** LSA secret used **directly** — the half IS the pre-key, fed
straight into `DecryptMasterKeyToMemoryEx`, with no HMAC/SID step (unlike the password path):

```
DPAPI_SYSTEM = LsaRetrievePrivateData("DPAPI_SYSTEM") = version(4) ‖ machine(20) ‖ user(20)
            (QuerySystemCredentials -> g_rgbSystemCredMachine / g_rgbSystemCredUser;
             GetSystemCredential(param_1): ==0 user half, !=0 machine half)
pre_key = dpapi_system_half(20)          # used as-is; NOT HMAC-SHA1(half, SID)
```

The **machine** half opens LOCAL_MACHINE keys and the **user** half the account's own keys; simplest
is to **try both**. The half feeds the same `DecryptMasterKeyToMemoryEx` (§15.4); only the credential
source differs. Modeled by `masterkey.parse_dpapi_system` + `decrypt_masterkey(blob, half)`. (On a
WinRE boot the halves come from `TryQuerySystemCredentialsFromWinRE`.)

Verified in `GetMasterKeyUserEncryptionKey` (0x20cc): after `CPSGetSystemCredential` writes the half
into the output-key buffer, the branch at `@239b–23ac` jumps **past** `DeriveWithHMAC_SHA1` for
LOCAL_MACHINE (`esi!=0`) and for account kinds `0x12 / 0x13 / 0x14` (SYSTEM / LocalService /
NetworkService) — so the raw half is the pre-key. Only kinds `0x5a / 0x5b / 0x63` (exotic virtual
accounts) fall through to `CPSGetUserName` + `DeriveWithHMAC_SHA1`, giving
`pre_key = HMAC-SHA1(half, username·UTF-16LE)`.

> Correction: an earlier draft modeled every machine/system key as `HMAC-SHA1(half, SID)` (mirroring
> the password path). That is wrong — for SYSTEM/LOCAL_MACHINE/service accounts the raw half is the
> pre-key, as the 0x20cc branch above shows (and as decrypting the real machine/system master keys
> confirms).

Separate: `GetLocalKeyUserEncryptionKey` (0x322c) computes `SHA-512(username ‖ machine ‖ user)` — that
is the **local BACKUP key** for the `BackupKey` sub-blob / recovery (`BuildLocalKey`, `BackupMasterKey`,
`RestoreMasterKey`), NOT the primary master-key file decryption.

### 15.1.1 DPAPI_SYSTEM — origin, on-disk storage, offline recovery

**Origin (it is not derived from anything).** `CreateSystemCredentials` (lsasrv.dll 0x34bb0) fills a
44-byte buffer with `BCryptGenRandom(NULL, buf, 0x2c, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`, overwrites the
first 4 bytes with `version = 1`, then writes it with `LsaStorePrivateData("DPAPI_SYSTEM")`. So the two
halves are simply 40 cryptographically-random bytes; there is no password, machine key or SYSKEY input.
It is created once, lazily: `GetSystemCredential` calls `QuerySystemCredentials` and, if it returns
`2` (not present), calls `CreateSystemCredentials` and re-queries.

**On-disk storage.** `DPAPI_SYSTEM` is an LSA secret. On disk it lives in the `SECURITY` hive under
`Policy\Secrets\DPAPI_SYSTEM\CurrVal`, wrapped by the LSA key hierarchy whose root is the SYSKEY /
bootkey. The at-rest layer is lsasrv's AES "LSP" path (confirmed on Win10/11):
`LsarRetrievePrivateData2 -> LsapDbQueryValueSecretAes -> LsapDecryptSecretValueWithLSPEncryptionKey
-> LspDecryptData -> LspCreateEncryptionKey`, using AES-256-CBC with a 1000-round SHA-256 key.
The SYSKEY is assembled from the class strings of the `JD` / `Skew1` / `GBG` / `Data` keys under
`SYSTEM\<ControlSet>\Control\Lsa` and permuted; the LSA key list is `SECURITY\Policy\PolEKList`
(pre-Win10 the RC4 `PolSecretEncryptionKey` path also exists in the binary).

**Retrieval.**
- *Online* (inside lsass, i.e. SYSTEM): `LsaRetrievePrivateData("DPAPI_SYSTEM")`. A non-SYSTEM caller —
  even an administrator — is denied; the service accounts never read it themselves, lsass reads it on
  their behalf during the RPC.
- *Offline* (from the hive files): SYSKEY (SYSTEM hive) → decrypt `PolEKList` with it (AES) → LSA key →
  decrypt `Secrets\DPAPI_SYSTEM\CurrVal` with the LSA key (AES) → `LSA_SECRET_BLOB` whose `Secret` is
  the 44-byte value (the route `secretsdump` / `mimikatz lsadump::secrets` take).

The toolkit here does **not** extract the secret itself: `masterkey` / `example` take the 44-byte
`DPAPI_SYSTEM` as input (hex) and derive the DP_KEK from it (`parse_dpapi_system`,
`dpapi_system_prekey`). Obtaining the secret — online as SYSTEM, or offline from the hives — is left
to the caller.

### 15.2 High-level flow

```
GetPreferredMasterKey(ctx, &guid, &pKey, &cbKey)
 ├─ CPSImpersonateClient -> OpenThreadToken + GetTokenInformation -> CPSRevertToSelf   (caller SID/LUID)
 ├─ CPSGetUserStorageArea(ctx, …, &pwszDir)        (<base>\Microsoft\Protect\<SID> ; see paths below)
 ├─ GetPreferredMasterKeyGuid(ctx, pwszDir, &guid) (Preferred file -> current master key GUID)
 ├─ GetMasterKey(…)                                 (↓ §15.3)
 ├─ SetPreferredMasterKeyGuid / UuidToStringW       (audit + rotation of an expired key)
 └─ InsertMasterKeyCache(ctx, LUID, guid, mk, 64)   (cache by LUID+GUID; later calls skip via SearchMasterKeyCache)
```

Since the master key is decrypted once and cached, `DeriveWithHMAC_SHA1` / the file
path runs only on a **cache MISS** (e.g. first use after boot/login).

**Where `CPSGetUserStorageArea` puts the store** (verified in the decompile; state separation OFF).
The path is `<base>\Microsoft\Protect\<SID>\`, with a `Preferred` file naming the current master
key GUID and `<GUID>` files alongside it. `<base>` and whether a `\User` suffix is appended depend
on the account kind (`param_1[0xc]`) and the LOCAL_MACHINE marker (`param_1[4]`):

| scope | base | path |
|---|---|---|
| user (kind 0/99) | `GetUserProfileDirectoryW` + `\AppData\Roaming` | `%APPDATA%\Microsoft\Protect\<userSID>` |
| LOCAL_MACHINE (`param_1[4]!=0`) | `GetSystemDirectoryW` | `%WinDir%\System32\Microsoft\Protect\S-1-5-18` |
| SYSTEM (kind 0x12, `param_1[4]==0`) | `GetSystemDirectoryW` | `%WinDir%\System32\Microsoft\Protect\S-1-5-18\User` |
| LocalService (0x13) | `GetSystemDirectoryW` | `%WinDir%\System32\Microsoft\Protect\S-1-5-19` |
| NetworkService (0x14) | `GetSystemDirectoryW` | `%WinDir%\System32\Microsoft\Protect\S-1-5-20` |
| virtual, WM etc. (0x5a/0x5b) | `GetUserDirFromRegistry` (ProfileList) | `<ProfileImagePath>\AppData\Roaming\Microsoft\Protect\<SID>` |

The only path difference between LOCAL_MACHINE and SYSTEM is the `\User` suffix (appended at the
`uVar35==0x12 && uVar30==0` branch). These scripts never build these paths — the caller passes the
right master key file; the table is only so you know **where to find it** on a real system. When
`RtlIsStateSeparationEnabled()` is true the system/service stores move to the per-profile path.

### 15.3 `GetMasterKey` — read the file, try credentials in order

```
GetMasterKey:
   ReadMasterKey(ctx, &MASTERKEY_STORED)
      └ mmap the file and split into 4 sub-blobs (MASTERKEY_STORED file layout):
          +0x00 version(4)=2   +0x04 unk(8)   +0x0C guid(72, UTF-16LE str)
          +0x54 unk(8)   +0x5C policy(4)
          +0x60 mkLen(8)  +0x68 bkLen(8)  +0x70 chLen(8)  +0x78 dkLen(8)
          +0x80 MasterKey (user-sealed) ‖ BackupKey (local) ‖ CredHist ‖ DomainKey (domain RSA)
   the user-sealed MasterKey sub-blob (= masterkey_blob, what decrypt_masterkey looks at):
          +0x00 version(4)  +0x04 salt(16)  +0x14 rounds(4)
          +0x18 hashAlg(4)  +0x1c cipherAlg(4)  +0x20 ciphertext
          ciphertext -> hmacSalt(16) ‖ hmac(digestLen) ‖ masterkey(64)

   ORDER OF ATTEMPTS (first success wins):
     1) ComputeMasterKeyUserEncryptionKey -> DeriveWithHMAC_SHA1 (CURRENT password pre-key)
                                          -> DecryptMasterKeyFromStorage
     2) GetMasterKeyUserEncryptionKey (variant)        -> DecryptMasterKeyFromStorage
     3) GetMasterKeyUserEncryptionKey (WinRE/local)    -> DecryptMasterKeyFromStorage
     4) GetMasterKeyUserEncryptionKey (CREDHIST / old password) -> DecryptMasterKeyFromStorage
     if all fail -> RestoreMasterKey (recovery with the backup key, §15.5)
```

**Critical behavior:** `GetMasterKey` does not make a single attempt; it tries several
sources in order, each producing a **different identity**. If the password changed, the
file may still be sealed under the **old** password's pre-key; then the current-password
attempt fails the HMAC (`0x80090020`), and a later CREDHIST identity opens the file. In
live debugging, if the first (current-password, failing) `DecryptMasterKeyToMemoryEx`
hit is captured, its output is garbage — the successful decryption is with a later
identity.

### 15.4 `DecryptMasterKeyToMemoryEx` — the actual KDF (XOR-feedback PBKDF2)

Signature (observed): `DecryptMasterKeyToMemoryEx(pbKey=pre_key, cbKey, pbBlob=mkBlob, cbBlob, allocFn, &pKeyOut, &cbOut, &alg, …)`.

```
① copy the blob to a work buffer, read the header by version:
     version == 1 -> legacy offsets (0x24-byte prefix)
     version != 1 -> v2:  salt @+0x04 (16B) · rounds @+0x14 · hashAlg @+0x18 · cipherAlg @+0x1c · ct @+0x20

② key material — PKCS5DerivePBKDF2 (an internal function called in a per-block loop):
     PKCS5DerivePBKDF2(pre_key, cbKey, salt=blob+4, hashAlg, rounds, blockIdx(i), out, remainingLen)
     NOTE: NOT standard PBKDF2. The difference (decompile + verified live): standard
     PBKDF2 feeds the previous U each round; this implementation feeds the ACCUMULATED
     XOR result (T) and loops rounds-1 times:
       T = HMAC-SHA512(pre_key, salt(16) ‖ INT32BE(i))          # U1
       (rounds-1) times:  T = T ⊕ HMAC-SHA512(pre_key, T)       # accumulated T fed back
     In the binary: the first HMAC (0x54a5) is before the loop; the loop counter runs
     r15d=1 to rounds (i.e. rounds-1 iterations); each iteration passes rbx=T (the output
     buffer) to HashData, not U_prev.
     => key||iv = _pkcs5_derive_pbkdf2( pre_key, salt, rounds ) -> keyLen+ivLen bytes
     key = out[:keyLen]   iv = out[keyLen:keyLen+ivLen]        (AES-256: 32 + 16)

③ decrypt + verify:
     BCryptGenerateSymmetricKey(key) -> BCryptDecrypt(AES-256-CBC, iv) -> cleartext
     cleartext = hmacSalt(16) ‖ storedHmac(digestLen) ‖ masterkey(64)        (AES256/SHA512: 16+64+64=144)
     calc = HMAC( HMAC(pre_key, hmacSalt), masterkey )   # double HMAC-SHA512
     memcmp(calc, storedHmac):  equal -> master key (64B)   ·   different -> HMAC failure
```

`GetIterationCount` is a separate helper: if hashAlg is SHA-512 it returns a base of
8000 (`0x1f40`), if SHA-1 18000, using a global override if present; but the round count
used in decryption is the **`rounds` field of the file**.

**NTSTATUS:**

```
0xC000000D / 0x80090005  invalid alignment / version / parameter
0x8007000E               LocalAlloc failed
0x80090020  NTE_FAIL     HMAC mismatch (wrong / old-password pre-key) -> GetMasterKey tries the next identity
```

### 15.5 CREDHIST and backup/recovery

- **CREDHIST** (`%APPDATA%\Microsoft\Protect\CREDHIST` + the `CredHist` sub-blob in the
  master key file): a **chain** of old password hashes; each entry is encrypted with the
  hash of the next (newer) password. When the password changes and the master key file
  remains sealed under the old password, DPAPI starts from the current password and walks
  the chain **from the end backward** (`GetPreviousCredentialHistory`), decrypting each
  entry with `DecryptCredentialHistory`; the resulting cleartext yields the previous
  password's SHA1 + NT hash (+SID), which opens the next entry. Thus from the current
  password all the **old password hashes** are reached -> old pre-keys -> master keys
  sealed under old passwords are opened. This is the last identity source in §15.3.

  The `DecryptCredentialHistory` crypto is **identical** to the master key path:
  `derived = HMAC-SHA1(pwdhash, SID)` -> `_pkcs5_derive_pbkdf2(derived, salt, rounds)`
  (XOR-feedback variant) -> AES-CBC. So the key that opens a CREDHIST entry is also a
  pre-key (not pwdhash directly — the SID is mixed in).

  **CREDHIST file format** (verified against a real file):
  ```
  [entry_0]…[entry_N] [footer(24B)]            # oldest to newest; footer at the end
  footer: version(4) guid(16) cbEntries(4 = total bytes before the footer)
  entry : +0x00 version  +0x04 guid(16)  +0x14 unk(4)  +0x18 revision(4)
          +0x1c hashAlg  +0x20 rounds  +0x24 sidLen  +0x28 cipherAlg
          +0x2c shaLen  +0x30 ntLen  +0x34 salt(16)  +0x44 SID  +.. ciphertext
  ```
  Cleartext = `prev_sha1(20) ‖ prev_nt(16, +4 zero)` = the previous password's hashes.

  **Live verification (VM):** current password 442026 -> `walk_credhist` decrypted the
  old password: `sha1 = da39a3ee…08709 = SHA1("")`, `nt = 31d6cfe0…c0 = MD4("")`. So in
  the VM the old password was **empty**, changed to 442026; the CREDHIST chain yielded
  this byte-for-byte.
- **Backup / recovery** (`RestoreMasterKey`): if all password/CREDHIST paths fail (e.g.
  an admin reset the password without knowing the old one -> CREDHIST broken), the
  `BackupKey`/`DomainKey` sub-blob in the file is decrypted with the domain/local backup
  key (RSA, MS-BKRP {3DDE7C30-…}). Outside the password chain.

**Python equivalent (CREDHIST):** instead of the full chain, the practical model is to
keep several **candidate pre-keys** (derived from the current + old passwords) and try
each; whichever one's HMAC holds is the one that opens the file. Write it from the
module's primitives (`decrypt_masterkey` + `derive_prekey`); there is no separate helper.

### 15.6 Verified model — `masterkey.py`

`masterkey.py` implements the algorithm in §15.4 and seals/unseals the master key
**itself**:

```
encrypt_masterkey(masterkey, pre_key)           : master key -> masterkey_blob   (PBKDF2->AES-CBC->double-HMAC)
decrypt_masterkey(masterkey_blob, pre_key)      : masterkey_blob -> (master key, hmac_ok)
prekey_from_password(password, sid)             : SHA1 -> HMAC-SHA1(SID) -> pre-key
parse_credhist / decrypt_credhist_entry / walk_credhist : the CREDHIST chain
```

Live KDNET verification (VM, successful `DecryptMasterKeyToMemoryEx`, ret=0):
```
  pre_key = 7a1851b2…fd24d0a7  (= HMAC-SHA1(SHA1("442026" UTF-16LE), SID))
  blob    = 02000000 f1db2307…  (salt=f1db2307…, rounds=8000, SHA512, AES-256)
  -> decrypt_masterkey output master key = 73201998…  (IDENTICAL to the kernel's, HMAC holds)
```
Also `decrypt_masterkey(encrypt_masterkey(mk,pk),pk) == mk` and `hmac_ok=False` on a
wrong pre-key. The top of the chain is confirmed too: `SHA1("442026")` = the captured
credential key, `HMAC-SHA1(pwdhash, SID\0)` = the captured pre-key. The model is now
verified end to end, live.

### 15.7 SYNCHIST — master key synchronization history (NON-crypto)

`%APPDATA%\Microsoft\Protect\<SID>\SYNCHIST` is **not a password store**; it is a
**fingerprint** kept to track when the master keys were last synchronized with the
domain backup.

```
SYNCHIST = version(4) ‖ hashAlg(4 = 0x800e SHA512) ‖ len(4 = 0x40) ‖ hash(64B)
```

- `GetMasterKeySyncHash` -> `HashMasterKeyFile` -> SHA-512 of the master key file (the
  file is opened with `OpenFileInStorageArea` and its content is hashed).
- `IsMasterKeySyncRequired` -> `OpenSyncHistoryFile` -> reads SYNCHIST with `ReadFile`,
  validates the header (`hashAlg==0x800e`, `len==0x40`), compares the 64B hash with the
  hash of the current master key(s) via `EnumerateMasterKeys`. On a mismatch ->
  `SynchronizeMasterKeys` (domain backup, MS-BKRP) is triggered.

Since there is no secret to decrypt inside, it adds no decrypt/encrypt capability to
`masterkey.py`. Related functions: `GetMasterKeySyncHash` 0x198a0 · `HashMasterKeyFile`
0x19a4c · `IsMasterKeySyncRequired` 0x1afec · `OpenSyncHistoryFile` 0x1ac24 ·
`SynchronizeMasterKeys` 0x318bc · `UpdateLastMasterKeySync` 0x3bbd8.

**Why is domain communication needed?** In a domain, each master key is backed up with
two things: the user's password-derived key **and** a **domain backup key** (an RSA pair
held on the DCs, the `MASTERKEY_STORED.DomainKey` sub-blob). The purpose: if an admin
resets the password, the CREDHIST chain breaks; then the master key can only be recovered
with the domain backup key (MS-BKRP, `{3DDE7C30-…}`). Therefore, every time a **new**
master key is generated (e.g. ~90-day rotation), its domain backup must also be created
on the DC — otherwise that key cannot be recovered. SYNCHIST tracks exactly this: "which
master keys have been synced with the DC?" A new key -> the SYNCHIST hash does not match
the current keys -> `IsMasterKeySyncRequired` true -> `SynchronizeMasterKeys` backs up the
new key to the DC. On a standalone machine (no domain — like this analysis machine,
`dsregcmd: AzureAdJoined NO`) a **local backup key** is used and there is no DC
communication; the mechanism still works but the target is local.

### 15.8 Address + Symbol Table — master key path (dpapisrv.dll, base 0x180000000)

```
GetPreferredMasterKey              0xcf80    get the caller's current master key
GetPreferredMasterKeyGuid          0xe0c0    Preferred file -> current GUID
CPSGetUserStorageArea              0x8b40    %APPDATA%\Microsoft\Protect\<SID>
GetMasterKey                       0x14d90   read the file + try identities in order
ReadMasterKey                      0x1c7c4   MASTERKEY_STORED parse (4 sub-blobs)
ComputeMasterKeyUserEncryptionKey  0x2e1c8   current password -> pre-key
GetMasterKeyUserEncryptionKey      0x20cc    other identity sources (CREDHIST/WinRE/local)
DeriveWithHMAC_SHA1                0x10bec   pre-key = HMAC-SHA1(pwdhash, SID)
DecryptMasterKeyFromStorage        0x3cf4    single-attempt wrapper -> ToMemoryEx
DecryptMasterKeyToMemoryEx         0x3e58    XOR-feedback PBKDF2 -> AES-CBC -> double-HMAC verify
PKCS5DerivePBKDF2                  0x52c0    the XOR-feedback KDF (per-block, internal function)
GetIterationCount                  0xefc4    SHA512->8000 / SHA1->18000 base (+global override)
RestoreMasterKey                   0x2490    recovery with the backup key (outside the password)
SearchMasterKeyCache               0x130d0   search the decrypted master key cache
InsertMasterKeyCache               0x134f8   cache the decrypted master key
```

---

## 16. Event Logging Surface (ETW / WPP / Audit) — note

Full enumeration deferred; the framework identified so far:

- **ETW (structured events):** provider **Microsoft-Windows-Crypto-DPAPI
  `{89FE8F40-CDCE-464E-8217-15EF97D4C7C3}`** (confirmed in the dpapisrv binary).
  `EtwEventRegister` / `EtwEventWriteTransfer` + `McTemplateU0*` / `McGenEventWrite`
  templates, the `Microsoft_Windows_Crypto_DPAPIEnableBits` enable flag. Event symbols
  (ETW_LOG_*): `DPAPI_PROTECT_FAILED` · `DPAPI_UNPROTECT_FAILED` ·
  `DPAPI_MASTER_KEY_CREATED/DELETED/INACCESIBLE/SYNCH` · `MASTER_KEY_BACKUP` ·
  `MASTERKEY_CRED_MATCH / CRED_MISMATCH` (password/CREDHIST match) ·
  `MASTERKEY_MISSING/NOT_FOUND` · `MASTERKEY_ENCRYPTION_FAILED` ·
  `CREDHIST_DECRYPTION_FAILED` · `DPAPI_PASSWORD_CHANGE_TRIGGERED` ·
  `BACKUPKEYSVC_STARTED/STOPPED/SETUP_FAILED`.
- **WPP (developer trace):** `EtwRegisterTraceGuidsW` / `EtwTraceMessage` +
  `WPP_GLOBAL_Control` + `WPP_SF_*` (many; off by default).
- **Security audit:** `CPSAudit` -> token SID + AuthenticationId -> forwards via
  `_guard_dispatch_icall` to lsasrv's audit function -> Security.evtx (DPAPI Activity,
  events 4692–4695; `4694/4695` only with the `CRYPTPROTECT_AUDIT 0x10` flag).

The full surface (client crypt32/dpapi ETW, kernel cng/ksecdd, lsasrv audit event IDs)
will be extracted when the relevant binaries are collected.

**Monitoring points (not yet enumerated):** This analysis fully covers the crypto chain;
the places where each critical step is *observable* via ETW/WPP/audit ("monitoring
points") are deferred as a separate phase. That is: it is known that "an event/trace is
produced here", while the exact mapping of which event ID + fields is left for later.
This does not affect the correctness of the crypto model.



---

## 17. dwFlags — per-flag behavior (verified against the binaries + public PDB)

Addresses are RVAs in `dpapisrv.dll` (base 0x180000000). `dwFlags = edi = [rbp+0x2f8]` in
`SPCryptProtect` (0x5ed0). Function names are from `dpapisrv.pdb` public symbols.

### 17.1 The blob flags field — write site + exact value (fully decoded)
```
@6034  and eax,0x20000010 ; or r14d,eax        ; r14d |= dwFlags & (AUDIT 0x10 | SYSTEM 0x20000000)
@6b51  mov [ctx+0x10],1 ; mov r14d,0x4          ; LOCAL_MACHINE branch: r14d |= 0x4
@6042  mov [rsp+0x5c],r14d                       ; spill accumulator
@6907  mov eax,[pPromptStruct+0x4]               ; dwPromptFlags  (pPromptStruct=[rbp+0x2f0])
@690a  test eax,0xffffffe4 ; jne <err>           ; validate dwPromptFlags subseteq 0x1b
@6917  and ecx,0x8                               ; ecx = dwPromptFlags & CRYPTPROTECT_PROMPT_STRONG
@693c  or edx,0x8 ; mov [rsp+0x5c],edx           ; if STRONG -> set blob flags bit 0x8
@64f2  mov [r14+0x14],edx                         ; edx=[rsp+0x5c] -> blob body +0x14 = FLAGS field
```
So: **blob.flags = (dwFlags & 0x20000014) | (0x8 if pPromptStruct->dwPromptFlags & PROMPT_STRONG)**.
Both terms are now verified with their write/compare sites (earlier the conditional 0x8 was
the "open" item; it is CRYPTPROTECT_PROMPT_STRONG, not an input dwFlags bit).

### 17.2 Per-flag
| Flag | Val | Cited site(s) | Verified behavior |
|---|---|---|---|
| UI_FORBIDDEN | 0x1 | — | No test in dpapisrv/dpapi/crypt32; no ERROR_PASSWORD_RESTRICTION constant in any. Per MSDN it forbids UI (fails if UI required); enforcement is in the external prompt-UI module (not supplied, not pursued). |
| LOCAL_MACHINE | 0x4 | `@5fe9`->`@6b49` | `mov [ctx+0x10],1`. `CPSGetUserStorageArea` (0x8b40) reads `[ctx+0x10]` (`@8f69/@8fdc`) and builds a FIXED machine path from `GetSystemDirectoryW` (`@9098`) + `\Microsoft\Protect` + `S-1-5-18` (ref `@968e`); a `\User` component also exists (ref `@8b84`). Bit 0x4 also recorded in blob flags (17.1). Derivation math unchanged. LOCAL_MACHINE lands in the **bare** `S-1-5-18\` (proven, 17.4); `S-1-5-18\User\` is the SYSTEM-as-user store. |
| CRED_SYNC | 0x8 | `@601b`->`@6d08` | Not a data op; produces no blob. Full chain: `InitiateSynchronizeMasterKeys` -> `QueueUserWorkItem(QueueSyncMasterKeysThreadFunc)` (background). That thread: `IsMasterKeySyncRequired` -> `SynchronizeMasterKeys` -> `SynchronizeSidMasterKeys`, which **enumerates the user's master-key files** (`FindFirstFileW`/`FindNextFileW` in `...\Protect\<SID>`), `GetMasterKey` (decrypt each), `UpdateDomainUserMasterKey` -> `EncryptMasterKeyToStorage` -> **`WriteMasterKey` (rewrites the MASTERKEY_STORED file on disk)** + `ReencryptMasterKey`/`InsertMasterKeyCache`; then `UpdateLastMasterKeySync` -> **`WriteFile` (rewrites the SYNCHIST file)**. Net on-disk effect under Protect\\<SID>: the `<GUID>` master-key files are re-sealed/rewritten (domain-backup/current-credential refresh) and `SYNCHIST` is updated. No data ciphertext is produced. |
| AUDIT | 0x10 | `@6034` | masked into blob flags (17.1); drives `CPSAudit` (`@751f`) + ETW (`McGenEventWrite`). No crypto change. |
| SYSTEM | 0x20000000 | protect `@6034`; unprot `@a0af`/`@a0b4` | PROTECT: only recorded into the blob flags field (no branch). UNPROTECT: the bit IS acted on — `@a0b4 bt esi,0x1d` tests the blob's stored SYSTEM bit and `@a0c0 test (dwFlags&SYSTEM)` the caller's; the two branches (SYSTEM-set vs not) select the master-key retrieval path through a critical-section-guarded CFG-indirect call (`@a314/@a3d6`) that was not statically named. Practical effect (like LOCAL_MACHINE): the blob's master key is the MACHINE key, so unprotect must use the machine store. |
| VERIFY_PROTECTION | 0x40 | see 17.3 | Not tested in dpapisrv; client-only return conversion. |
| NO_RECOVERY | 0x20 | — | header-defined; no test found anywhere in this binary. |
| CRED_REGENERATE | 0x80 | — | header-defined; no test found anywhere in this binary. |

### 17.3 VERIFY_PROTECTION / 0x91012 (produced server-side)
`GetDefaultAlgInfo` (0xc400) returns the host DEFAULT cipher+hash alg ids: `0x6610` (AES-256) /
`0x800e` (SHA-512) by default, overridable by the registry policy under `...\Protect` (`Encr Alg`/
`MAC Alg`, read by `UpdateGlobals`; e.g. legacy 3DES/SHA-1). In `SPCryptUnprotect` the default and
the blob's algorithms are each passed through `GetBCryptProviderHandle` (0x5b20) `@b214/@b223`,
which returns the algorithm's **length in bits** (cipher: BCrypt `KeyLengths` max; hash:
`HashDigestLength`*8), cached at `[entry+0xc]`. Then `@b247`:
```
cmp default_cipher_bits, blob_cipher_bits ; ja  @b25a   -> need reprotect
cmp default_hash_bits,   blob_hash_bits   ; jbe @a998   -> OK ; else @b25a
@b25a mov ebx,0x91012   (CRYPT_I_NEW_PROTECTION_REQUIRED)
```
Reprotect iff the host default is longer on cipher OR hash. NOT gated on `dwFlags&0x40`; the client
(`crypt32 @926e4/@92907`, `dpapi!CryptUnprotectDataNoUI @1800012d9`) uses 0x40 only to turn 0x91012
into a TRUE return. The compare is by raw key/digest BIT LENGTH, so 3DES (192-bit) ranks above
AES-128 (128-bit) — as Windows computes. Modelled by `dpapi_protect.verify_protection`.

### 17.4 SYSTEM-account context vs LOCAL_MACHINE store
Verified from `CPSGetUserStorageArea` (strings: `ProfileImagePath` @0x44938, `AppData\Roaming`
@0x434f2, `\Microsoft\Protect\` @0x43478): the per-user path resolves the user's profile dir from
the registry `ProfileImagePath` (keyed by SID), then appends `\AppData\Roaming\Microsoft\Protect\<SID>`.
Now fully decoded from the `CPSGetUserStorageArea` decompile. Two ctx fields drive it:
`ctx+0x10` (= the LOCAL_MACHINE marker, call it LM) and `ctx+0x30` (= a well-known-account KIND;
0x12 -> S-1-5-18, 0x13 -> S-1-5-19 LocalService, 0x14 -> S-1-5-20 NetworkService, 0 -> ordinary user).

Base directory:
- Ordinary user (LM==0, kind==0): `GetUserProfileDirectoryW(token)` + `\AppData\Roaming` + `\Microsoft\Protect\` + `<caller SID>`.
- LM!=0, or a well-known system kind: `GetSystemDirectoryW()` (= `C:\Windows\System32`) + `\Microsoft\Protect\` + the SID string. The SID string is forced to `"S-1-5-18"` when LM!=0 or kind==0x12.

The `\User` suffix: appended **iff `kind==0x12 (S-1-5-18)` AND `LM==0`** (decompile: `if ((uVar35==0x12)&&(uVar30==0)){ uVar36=10; local_7e8=&"\\User"; }`). Therefore, PROVEN:
- **`...\System32\Microsoft\Protect\S-1-5-18\` (bare) = CRYPTPROTECT_LOCAL_MACHINE keys** (LM!=0 -> SID forced S-1-5-18, `\User` NOT appended).
- **`...\System32\Microsoft\Protect\S-1-5-18\User\` = the Local System account protecting as ITSELF** (kind 0x12, LM==0 -> SID S-1-5-18 + `\User`).

So the Local System account's own keys live in `S-1-5-18\User`, and the LOCAL_MACHINE keys in bare `S-1-5-18`; both under System32 because machine/system keys must not roam. The full layout is collected in §18. So a bare `S-1-5-18\<GUID>`
(Local System acting as a normal user principal, its own profile keys) and `S-1-5-18\User\<GUID>`
(the LOCAL_MACHINE machine-wide keys under System32) are DIFFERENT key sets. `CPSSetWellKnownAccount(ctx, 0x12)`
is also called in a ctx-kind branch (`@6ce9`, when `[ctx+0x30]` in {0x13,0x14}); account id 0x12 resolves
to the textual SID **"S-1-5-18"** (Local System) — verified via `CPSGetTextualSidForWellKnownAccount`
(`@0x214f4 sub ecx,0x12 ; je 0x21535` -> string `0x180043598` = "S-1-5-18").

### 17.5 SYSTEM flag — where it is acted on
`0x20000000` is tested in dpapisrv only at `@6034` (protect: masked into the blob flags field) and
on unprotect at `@a0af/@a0b4` (`bt esi,0x1d` on the blob's stored SYSTEM bit + `test dwFlags&SYSTEM`).
Protect records it into the stored blob flags (`local_34c = … | (param_10 & 0x20000010)` @313 →
`puVar3[5] = local_34c` @704) **and** branches on it for input handling; unprotect branches on the
blob's stored bit to drive the master-key lookup path (a cache list-walk via the `0x40010` comparator
thunk). It marks the blob **system/trusted-scope**. Note this is *not* the same as LOCAL_MACHINE: a
LOCAL_MACHINE blob is decryptable by any local user, whereas SYSTEM is used only by internal
(in-process) dpapisrv callers — even if both resolve a machine-scoped key file, the access semantics differ.

**Protect-side input branch — what `(param_10 & 0x60000000)` actually does (@540).** `0x60000000` =
SYSTEM `0x20000000` | `0x40000000`. It selects how the plaintext input is pre-processed before the
common encrypt+MAC block (`LAB_1800062ee`):

- **Bit CLEAR — ordinary RPC path (@801+):** requires `cbIn >= 8 && cbIn % 8 == 0`, then
  `RpcImpersonateClient` → `SystemFunction041(param_4, cbIn, 2)` (**transit-DECRYPT** the input in
  place, undoing the client's `RtlEncryptMemory` wrap @826) → `RevertToSelf` → read+validate the last
  byte as the pad length and **strip** it (`uVar10 -= pad` @851) → fall into the encrypt block.
- **Bit SET — internal/direct path (@540→`LAB_1800062ee`):** jumps **straight** to the encrypt block,
  **skipping** the multiple-of-8 check, `RpcImpersonateClient`, the `SystemFunction041` transit-decrypt,
  `RevertToSelf`, and the padding strip. The input `param_4` is taken as **raw cleartext as-is**.

Meaning: the `0x60000000` branch is "the input is already clear and delivered in-process — don't undo a
transit wrap, don't impersonate, just encrypt it." It only makes sense for an internal (in-process) caller
that invoked `SPCryptProtect` **directly** (not over RPC), whose input never passed through the client-side
`RtlEncryptMemory`. This dovetails with `s_SSCryptProtectData`: because the RPC dispatch rejects
`0x20000000` with `0x57` before entry, an RPC client always takes the transit-decrypt+impersonate path,
and the `0x60000000` branch is reachable only internally.

**Caller-facing reality (why `--flag SYSTEM` cannot be driven from this project).** The dpapisrv
branches above only ever run for a *trusted* caller. `0x20000000` sits in the CRYPTPROTECT reserved
value range, not in the public input set (`0x1`–`0x80`). MSDN is explicit for both APIs: a normal
application may call `CryptProtectData`/`CryptUnprotectData` and the call *"fails only if
CRYPTPROTECT_SYSTEM is specified"*; the bit is usable solely by an internal (in-process) caller. Empirically,
`protect --text selam --flag SYSTEM` returns **`[WinError 87] ERROR_INVALID_PARAMETER`**, and it does
so **even under the SYSTEM account** (`psexec -s`). The error code is decisive: a *privilege* gate
would surface as `5 ACCESS_DENIED` or `1314 ERROR_PRIVILEGE_NOT_HELD`, whereas `87` is a parameter
rejection — the reserved bit is refused before any master-key access is attempted, so no amount of
token elevation changes the outcome.

**Where the 87 actually comes from (pinned from the `CryptProtectDataNoUI` decompile).** It is *not*
generated by the client stub. `CryptProtectDataNoUI` (dpapi.dll ord 1, rva 0x1330) produces `0x57`
locally in exactly two spots, neither tied to `dwFlags`: (1) a null `pDataOut`/`pDataIn`/
`pDataIn->pbData` check, and (2) a padding integer-overflow guard
(`uVar7 = 8-(cb&7); if (uVar7+cb < cb) → 0x57`), i.e. only when `cbData` is within 8 of `0xFFFFFFFF`.
Crucially, the function body **never reads `dwFlags`** (nor `szDataDescr`, `pOptionalEntropy`,
`pvEntropy2`, `cbEntropy2`): it only pads the input, transit-encrypts the copy with
`SystemFunction040(buf, len, 2)`, and ships everything to the server via
`NdrClientCall3(&PTR_PTR_180003000, 0, …)`, which marshals the remaining args through the MIDL format
string. Therefore the SYSTEM-flag `87` is the **return value of `NdrClientCall3`** — it is handed back
from dpapisrv, not decided on the client. So the chain is: the reserved bit is forwarded unexamined, the
server refuses it, and the stub just copies that code into `SetLastError`. This also corrects an earlier
guess: the rejection is **server-side**, *not* a "front-door" check in the NoUI export.

**Exact instruction (pinned from `s_SSCryptProtectData`, the opnum-0 RPC dispatch) — no rpcrt4 needed:**

```c
ulonglong s_SSCryptProtectData(..., uint param_10 /*dwFlags*/, ...) {
    if (g_fDPAPIInitialized == 0)          uVar5 = 0x54f;      // not initialized
    else if ((param_10 >> 0x1d & 1) == 0) {                     // bit 29 (0x20000000 SYSTEM) CLEAR
        CPSCreateServerContext(...);
        SPCryptProtect(...);                                    // the real work
        ...
    }
    else                                   uVar5 = 0x57;       // SYSTEM bit SET -> 87, nothing done
    return uVar5;
}
```

`param_10 >> 0x1d & 1` tests bit 29 = `0x20000000`. When an RPC caller sets it, the dispatch returns
`0x57` (`ERROR_INVALID_PARAMETER`) **before** `CPSCreateServerContext` and **before** `SPCryptProtect` —
no token is examined, which is exactly why elevating to the SYSTEM account changes nothing. Corollary:
`SPCryptProtect`'s own `(param_10 & 0x60000000)` branch (crypt32p.cpp line ~540) is **unreachable from
RPC with the SYSTEM bit** — `s_SSCryptProtectData` bounces it first — so that branch serves only
internal/direct callers (lsass protecting system data), confirming SYSTEM is a trusted/internal-only bit.

The unprotect dispatch `s_SSCryptUnprotectData` has the **same gate and shape**: `g_fDPAPIInitialized==0
→ 0x54f`; `(param_10 >> 0x1d & 1)` (SYSTEM bit) set `→ 0x57` before any work; otherwise `param_5 < 0x14
→ 0x0D` (input shorter than the blob header), then `CPSCreateServerContext`, then the blob version check
`*pbIn != 1 → 0x0D`, and only then `SPCryptUnprotect(pbIn+0x14, cbIn-0x14, …)` — i.e. it strips the
0x14-byte header before handing the body to `SPCryptUnprotect`. So `--flag SYSTEM` fails identically on
both protect and unprotect, at the RPC dispatch, for the same reason.

Consequence for the model: `SYSTEM` is kept only as a *stored-blob* flag for decoding
(`dpapi_protect.CRYPTPROTECT_SYSTEM`); it is **not** offered as a caller `--flag`, because from a
user-mode process it can never succeed. (To get machine-wide decryptable data from an ordinary process,
use `LOCAL_MACHINE 0x4`.)

---

## 18. DPAPI master-key storage locations

`CPSGetUserStorageArea` (dpapisrv.dll 0x8b40) picks the directory a master key lives in from
two context fields: the account KIND (`ctx+0x30`) and the LOCAL_MACHINE marker (`ctx+0x10`,
set by the LOCAL_MACHINE protect branch). Decoded from the decompile:

```
ordinary user   (kind 0, LM 0) : GetUserProfileDirectoryW(token) + "\AppData\Roaming"
                                  + "\Microsoft\Protect\" + <caller SID>
LOCAL_MACHINE    (LM != 0)      : GetSystemDirectoryW() + "\Microsoft\Protect\S-1-5-18"        (bare)
Local System     (kind 0x12,LM 0): GetSystemDirectoryW() + "\Microsoft\Protect\S-1-5-18\User"
other well-known (kind 0x13/0x14): SID forced to S-1-5-19 / S-1-5-20, machine base
kind 0x5a / 0x5b                 : SID via CPSGetTextualSidForWellKnownAccount + GetUserDirFromRegistry
```

Decision rule for the trailing `\User` (decompile, line "if ((uVar35==0x12)&&(uVar30==0))"):
appended **iff account KIND == 0x12 (S-1-5-18) AND LOCAL_MACHINE marker == 0**.

| On-disk directory | Scope | How reached |
|---|---|---|
| `%APPDATA%\Microsoft\Protect\<user SID>` | per user | GetUserProfileDirectoryW + `\AppData\Roaming` |
| `%WINDIR%\System32\Microsoft\Protect\S-1-5-18` | machine (CRYPTPROTECT_LOCAL_MACHINE) | LM != 0 |
| `%WINDIR%\System32\Microsoft\Protect\S-1-5-18\User` | the SYSTEM account's own data | kind 0x12, LM 0 |

Machine/system keys use `GetSystemDirectoryW` (a fixed System32 path), never the roaming
profile, so they do not roam and are available before any profile loads. `%APPDATA%` for a
SYSTEM-context process would resolve under `...\System32\config\systemprofile\AppData\Roaming`,
but DPAPI does not put the machine/system master keys there — it uses the fixed System32 path
above. Each directory also holds a `Preferred` file (current GUID + rotation time, §data_structures)
and, per-user, may hold `CREDHIST` / `SYNCHIST`.

Well-known account KIND values seen in `CPSGetTextualSidForWellKnownAccount` (0x214f4):
`0x12 -> S-1-5-18` (LocalSystem), `0x13 -> S-1-5-19` (LocalService), `0x14 -> S-1-5-20`
(NetworkService); `0x5a/0x5b` resolve via the registry.
