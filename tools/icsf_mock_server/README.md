# ICSF Mock LDAP Server

> ⚠️ **FOR TESTING ONLY — DO NOT USE IN PRODUCTION**
>
> This server is an insecure test stub.  It accepts every bind credential
> without verification, stores all key material unprotected in process memory,
> and provides no access control, audit logging, or key-management security of
> any kind.  It must never be exposed on a network or used to protect real data.

A self-contained Python 3 mock of the z/OS ICSF LDAP interface, designed to
let you run the openCryptoki ICSF token driver and the `pkcsicsf` configuration
tool without a real z/OS system.  **It is intended solely for development and
CI testing on loopback interfaces.**

## Implemented services

### Token management (`pkcsicsf` tool)

| ICSF service | Tag | Operation |
| --- | --- | --- |
| `CSFPTRC` | 14 | Create token (`TOKEN RECREATE`) or copy object (`OBJECT COPY`) |
| `CSFPTRD` | 15 | Destroy token (`TOKEN`) |
| `CSFPTRL` | 16 | List tokens (`TOKEN`) |

### Object management (ICSF token driver)

| ICSF service | Tag | Operation |
| --- | --- | --- |
| `CSFPTRC` | 14 | Create object (`OBJECT`) |
| `CSFPTRD` | 15 | Destroy object (`OBJECT`) |
| `CSFPTRL` | 16 | List objects (`OBJECT`, `OBJECT ALL`) |
| `CSFPGAV` | 3 | Get object attributes |
| `CSFPSAV` | 11 | Set object attributes |

### Cryptographic operations

| ICSF service | Tag | Operation | Notes |
| --- | --- | --- | --- |
| `CSFPDMK` | 1 | Derive multiple keys (`CKM_SSL3_KEY_AND_MAC_DERIVE`, `CKM_TLS_KEY_AND_MAC_DERIVE`) | SSL3 / TLS key and MAC material derivation; returns 4 key handles + IVs |
| `CSFPDVK` | 2 | Derive key (EC-DH / `CKM_ECDH1_DERIVE`, PKCS-DH / `CKM_DH_PKCS_DERIVE`, SSL-MS / `CKM_SSL3_MASTER_KEY_DERIVE`) | Real ECDH and DH via OpenSSL; X9.63 KDF; SSL 3.0 master secret derivation |
| `CSFPGSK` | 5 | Generate secret key (AES/DES/DES2/3DES) | `os.urandom` key material |
| `CSFPGKP` | 4 | Generate RSA/EC/DSA/DH key pair | Real key generation via libcrypto |
| `CSFPSKE` | 13 | Symmetric key encrypt | Real AES/DES/DES2/3DES ECB/CBC/CBC-PAD via libcrypto ctypes; multipart INITIAL/CONTINUE/FINAL chaining |
| `CSFPSKD` | 12 | Symmetric key decrypt | Real AES/DES/DES2/3DES ECB/CBC/CBC-PAD via libcrypto ctypes; multipart INITIAL/CONTINUE/FINAL chaining |
| `CSFPPKS` | 9 | Private key sign / RSA decrypt | Real RSA/ECDSA/DSA via libcrypto |
| `CSFPPKV` | 10 | Public key verify / RSA encrypt | Real RSA/ECDSA/DSA verification via libcrypto |
| `CSFPHMG` | 6 | HMAC generate | Real `hmac.new()` using stdlib; SHA-1/224/256/384/512, MD5, SHA3-*, SSL3-SHA/MD5; multipart FIRST/MIDDLE/LAST |
| `CSFPHMV` | 7 | HMAC verify | Real `compare_digest`; same algorithms as HMG; multipart FIRST/MIDDLE/LAST |
| `CSFPOWH` | 8 | One-way hash sign/verify | Real RSA/ECDSA/DSA via libcrypto backends; multipart FIRST/MIDDLE/LAST chaining |
| `CSFPWPK` | 18 | Wrap key | AES/DES/3DES CBC-PAD or RSA-PKCS (`PKCS-1.2`); private keys wrapped as PKCS#8 |
| `CSFPUWK` | 17 | Unwrap key | AES/DES/3DES CBC-PAD or RSA-PKCS decrypt; restores RSA/EC private keys from PKCS#8 |

SKE/SKD use real AES/DES/DES2/3DES (ECB, CBC, CBC-PAD) via OpenSSL `libcrypto`
through `ctypes` — no third-party Python packages required.  Known-answer tests
(KATs) with published NIST vectors pass.  WPK/UWK support both AES/DES/3DES
CBC-PAD and RSA-PKCS (`PKCS-1.2`) wrapping; private keys are serialised to/from
PKCS#8 DER before wrap/unwrap.  DVK uses `EVP_PKEY_derive` for real ECDH and
OpenSSL DH for PKCS-DH.

All state is in-memory.  Tokens and objects disappear when the server restarts.

## Requirements

- Python 3.8 or later
- **No third-party packages required.**  AES/3DES operations use OpenSSL's EVP
  API via `ctypes` — `libcrypto.so` is already present on any system running
  openCryptoki (it is a dependency of the LDAP stack).

## Quick start

### 1. Start the server

```sh
# Plain LDAP on 127.0.0.1:1389  (no root required)
python tools/icsf_mock_server/server.py --verbose

# Pre-create a token at startup:
python tools/icsf_mock_server/server.py --token MYTOKEN --verbose

# TLS with SASL EXTERNAL (client certificate authentication):
# 1. Generate a self-signed server certificate
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout server.key -out server.crt -days 365 -subj '/CN=icsf-mock'
# 2. Generate a client certificate signed by that server certificate
#    (the server cert acts as the CA for testing purposes)
openssl req -newkey rsa:2048 -nodes \
    -keyout client.key -out client.csr -subj '/CN=testuser'
openssl x509 -req -in client.csr -CA server.crt -CAkey server.key \
    -CAcreateserial -out client.crt -days 365
# 3. Start the server with TLS enabled on port 1636 (ldaps conventional port).
#    --cacert tells the server which CA to trust when verifying client certs;
#    without it Python falls back to the system CA bundle and rejects the
#    self-signed client certificate with CERTIFICATE_VERIFY_FAILED.
#    The server wraps every connection in TLS immediately, so clients must
#    connect with ldaps:// (TLS-from-the-start), not ldap://.
python tools/icsf_mock_server/server.py \
    --cert server.crt --key server.key --cacert server.crt \
    --port 1636 --verbose
```

### 2. Run `pkcsicsf` to add the token

`pkcsicsf -a` does all configuration automatically: it adds a slot entry to
`opencryptoki.conf` and writes the ICSF-specific `TESTTOKEN.conf` file
(containing the LDAP URI, bind DN, and mechanism).  No manual editing of
config files is required.

```sh
# List available tokens on the mock server (any password accepted)
pkcsicsf -l \
  -u ldap://127.0.0.1:1389 \
  -b "cn=testuser,dc=example,dc=com" \
  -m simple

# Add a new slot backed by the mock token TESTTOKEN (run as root)
pkcsicsf -a TESTTOKEN \
  -u ldap://127.0.0.1:1389 \
  -b "cn=testuser,dc=example,dc=com" \
  -m simple
```

After `pkcsicsf -a` completes, restart `pkcsslotd` so the new slot becomes
visible:

```sh
systemctl restart pkcsslotd
```

For SASL EXTERNAL authentication, use the client certificate and key generated
in step 1 above.  Note the `ldaps://` scheme and port 1636 — the server wraps
the connection in TLS immediately, so a plain `ldap://` URI causes the
"wrong version number" handshake failure.

Because the server certificate is self-signed, `libldap` rejects it by
default ("Can't contact LDAP server (-1)") unless you disable server
certificate verification in the ldap client configuration.  Add the
following line to `/etc/openldap/ldap.conf` (or `~/.ldaprc`) before running
`pkcsicsf`:

```text
TLS_REQCERT never
```

Then run:

```sh
pkcsicsf -a TESTTOKEN \
  -u ldaps://127.0.0.1:1636 \
  -m sasl \
  -c client.crt \
  -k client.key \
  -C server.crt
```

### 3. Object management with the ICSF token driver

Pre-seed test objects at startup so `C_FindObjects` and
`C_GetAttributeValue` have something to return:

```sh
# Start with one token and a mix of test objects
python tools/icsf_mock_server/server.py \
  --token TESTTOKEN \
  --object TESTTOKEN:myaeskey:aes \
  --object TESTTOKEN:mydeskey:des \
  --object TESTTOKEN:mydes3key:des3 \
  --object TESTTOKEN:myhmackey:generic-secret \
  --object TESTTOKEN:myrsakey-pub:rsa-pub \
  --object TESTTOKEN:myrsakey-priv:rsa-priv \
  --object TESTTOKEN:mydsakey-pub:dsa-pub \
  --object TESTTOKEN:mydsakey-priv:dsa-priv \
  --object TESTTOKEN:mydhkey-pub:dh-pub \
  --object TESTTOKEN:mydhkey-priv:dh-priv \
  --object TESTTOKEN:myeckey-pub:ec-pub \
  --object TESTTOKEN:myeckey-priv:ec-priv \
  --object TESTTOKEN:mycert:cert \
  --verbose
```

`--object` format: `TOKEN:LABEL:CLASS` where CLASS is one of:
`aes`, `des`, `des2`, `des3`, `generic-secret`,
`rsa-pub`, `rsa-priv`, `dsa-pub`, `dsa-priv`, `dh-pub`, `dh-priv`,
`ec-pub`, `ec-priv`, `cert`
(default `aes`).

Each pre-seeded object is created with **all** PKCS#11-defined attributes
for its class (common object attributes plus class-specific attributes),
using standard defaults for any attribute not explicitly supplied.

Once the slot is configured via `pkcsicsf -a TESTTOKEN`, use `p11sak`:

```sh
export PKCS11_USER_PIN=01234567
export SLOT=0

# List all keys (triggers C_FindObjectsInit → TRL → GAV per object)
p11sak list-key --slot $SLOT --pin $PKCS11_USER_PIN

# List only AES keys
p11sak list-key aes --slot $SLOT --pin $PKCS11_USER_PIN

# List all keys in long format (all attributes)
p11sak list-key --slot $SLOT --pin $PKCS11_USER_PIN --long
```

### 4. Crypto operations with the ICSF token driver

`p11sak` is a key management tool — it generates, lists, removes, copies,
imports, and exports keys, but does not perform encrypt/decrypt/sign/verify
operations.  Those are covered by `pkcs11-tool` further below.

```sh
export PKCSLIB=/usr/local/lib/pkcs11/libopencryptoki.so

# Generate a new AES-256 key (triggers CSFPGSK)
p11sak gen-key aes 256 \
  --slot $SLOT --pin $PKCS11_USER_PIN \
  --label myaes --attr ENCRYPT:DECRYPT

# Generate a 2048-bit RSA key pair (triggers CSFPGKP)
p11sak gen-key rsa 2048 \
  --slot $SLOT --pin $PKCS11_USER_PIN \
  --label myrsa:myrsa --attr ENCRYPT:SIGN

# Generate an EC P-256 key pair (triggers CSFPGKP)
p11sak gen-key ec prime256v1 \
  --slot $SLOT --pin $PKCS11_USER_PIN \
  --label myec:myec --attr VERIFY:SIGN

# List all keys after generation
p11sak list-key --slot $SLOT --pin $PKCS11_USER_PIN

# Remove the AES key (triggers CSFPTRD OBJECT)
p11sak remove-key aes \
  --slot $SLOT --pin $PKCS11_USER_PIN \
  --label myaes --force
```

`p11sak` does not perform encrypt/decrypt/sign/verify operations.
Use `pkcs11-tool` for those:

```sh
# Encrypt with AES-CBC (triggers CSFPSKE) and decrypt (triggers CSFPSKD)
echo -n "Hello world" | \
  pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --encrypt --mechanism AES-CBC --label myaes -o /tmp/enc.bin

pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --decrypt --mechanism AES-CBC --label myaes -i /tmp/enc.bin

# Sign with RSA (triggers CSFPPKS) and verify (triggers CSFPPKV)
echo -n "Hello world" | \
  pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --sign --mechanism SHA256-RSA-PKCS --label myrsa -o /tmp/sig.bin

pkcs11-tool --module "$PKCSLIB" --slot $SLOT \
  --login --pin $PKCS11_USER_PIN \
  --verify --mechanism SHA256-RSA-PKCS --label myrsa \
  --input-file /tmp/message.bin --signature-file /tmp/sig.bin
```

### 5. Debugging

Run with `--verbose` to get DEBUG-level logs including hex dumps of every
ICSF request and response payload — invaluable for diagnosing BER encoding
mismatches:

```sh
python tools/icsf_mock_server/server.py --token TESTTOKEN --verbose 2>&1 | tee mock.log
```

## Architecture

```text
tools/icsf_mock_server/
├── server.py          LDAPv3 TCP listener, message framing, op dispatch
├── ber_codec.py       BER encode/decode for ICSF request/response envelopes
├── token_store.py     Thread-safe in-memory token and object registry
├── pkcs11_const.py    PKCS#11 CKA_*/CKO_*/CKK_*/CKM_* constants
├── obj_attrs.py       PKCS#11-compliant attribute completion for all object classes
├── cipher_backend.py  AES/DES/3DES ECB/CBC/CBC-PAD via ctypes → libcrypto
├── rsa_backend.py     Real RSA sign/verify/encrypt/decrypt via libcrypto
├── ec_backend.py      Real ECDSA sign/verify via libcrypto
├── dh_backend.py      Real DH key agreement via libcrypto
├── dsa_backend.py     Real DSA sign/verify via libcrypto
├── spki_backend.py    Pure-Python SubjectPublicKeyInfo DER builder
└── handlers/
    ├── __init__.py
    ├── dmk.py         CSFPDMK — derive multiple keys              (tag 1)
    ├── dvk.py         CSFPDVK — derive key (EC-DH / SSL-MS)      (tag 2)
    ├── gav.py         CSFPGAV — get attribute value               (tag 3)
    ├── gkp.py         CSFPGKP — generate key pair                 (tag 4)
    ├── gsk.py         CSFPGSK — generate secret key               (tag 5)
    ├── hmg.py         CSFPHMG — HMAC generate                     (tag 6)
    ├── hmv.py         CSFPHMV — HMAC verify                       (tag 7)
    ├── owh.py         CSFPOWH — one-way hash sign/verify          (tag 8)
    ├── pks.py         CSFPPKS — private key sign/decrypt          (tag 9)
    ├── pkv.py         CSFPPKV — public key verify/encrypt         (tag 10)
    ├── sav.py         CSFPSAV — set attribute value               (tag 11)
    ├── skd.py         CSFPSKD — symmetric key decrypt             (tag 12)
    ├── ske.py         CSFPSKE — symmetric key encrypt             (tag 13)
    ├── trc.py         CSFPTRC — create token/object               (tag 14)
    ├── trd.py         CSFPTRD — destroy token/object              (tag 15)
    ├── trl.py         CSFPTRL — list tokens/objects               (tag 16)
    ├── uwk.py         CSFPUWK — unwrap key                        (tag 17)
    ├── wpk.py         CSFPWPK — wrap key                          (tag 18)
    └── hmac_state.py  Server-side session store for multipart HMAC
```

### Wire protocol summary

Every ICSF call is an LDAPv3 **ExtendedRequest** with OID `1.3.18.0.2.12.83`.
The request body and response body are DER-encoded sequences containing:

- A 44-byte **handle** (token name padded to 32 bytes + 8-byte hex sequence
  number + 1-byte object type `'T'`/`'S'` + 3 bytes padding)

- A **rule array** of 8-byte space-padded keyword items (`TOKEN`, `OBJECT`,
  `RECREATE`, `ALL`, `KEY`, `AES`, `DES3`, `ONLY`, `SHA-256`, etc.)

- A **service-tag-specific** context-constructed TLV whose tag number
  identifies the ICSF service (1=DMK, 2=DVK, 3=GAV, 4=GKP, 5=GSK, 6=HMG,
  7=HMV, 8=OWH, 9=PKS, 10=PKV, 11=SAV, 12=SKD, 13=SKE, 14=TRC, 15=TRD,
  16=TRL, 17=UWK, 18=WPK)

See [`ber_codec.py`](ber_codec.py) for the full encoding and
[`usr/lib/icsf_stdll/icsf.c`](../../usr/lib/icsf_stdll/icsf.c) for the
authoritative client-side reference.

## Limitations

- No persistent storage.  Restart = empty state.

- Authentication is always accepted (suitable for testing only).

- Three transport modes exist for LDAP; the mock server supports two of them:

  - **Plain** (`ldap://`, no TLS) — always works; suitable for loopback
    testing where no encryption is needed.

  - **TLS-from-the-start** (`ldaps://`) — the TCP connection is wrapped in
    TLS immediately, before any LDAP traffic.  The mock server supports this
    when started with `--cert` and `--key`; the client connects to an
    `ldaps://` URI or an `ldap://` URI on the TLS port.

  - **StartTLS** (`ldap://` followed by an LDAP `StartTLS` extended
    operation, OID `1.3.6.1.4.1.1466.20037`) — the connection begins as
    plain LDAP and then upgrades to TLS mid-session via an
    `ExtendedRequest`.  The mock server does **not** implement this: it only
    handles the ICSF extended-operation OID (`1.3.18.0.2.12.83`), so a
    StartTLS request returns `unwillingToPerform`.  If the ICSF token driver
    is configured with `mech = starttls`, it will fail to connect.

- Concurrent connections are fully supported (one thread per connection).

- No LDAP access-control.  Any bind DN is accepted.

- SKE/SKD/WPK/UWK use real AES-CBC-PAD (NIST KAT-compatible).

- DVK supports three derivation variants: EC-DH (`CKM_ECDH1_DERIVE`),
  PKCS-DH (`CKM_DH_PKCS_DERIVE`), and SSL-MS (`CKM_SSL3_MASTER_KEY_DERIVE`).
  For EC-DH, the six KDFs documented by ICSF z/OS are supported: `CKD_NULL`,
  `CKD_SHA1_KDF`, `CKD_SHA224_KDF`, `CKD_SHA256_KDF`, `CKD_SHA384_KDF`,
  `CKD_SHA512_KDF` (all via ANSI X9.63).

- Multi-part HMAC (FIRST/MIDDLE/LAST chaining) uses server-side session state
  to accumulate data across calls, but the session store is in-memory only.

- EC key pair generation produces real EC key material via OpenSSL.
  RSA key pair generation uses the same real-RSA backend.
