# OFFLINE EXAM CHEAT SHEET — Which function should I call?

## Identify the requested security operation

| Question says | Module/function | Notes |
|---|---|---|
| AES-128/192/256 encrypt text/file | `crypto_tools.symmetric_encrypt(data, 'AES', bits, mode)` | `data` is bytes; returns `(envelope,key)` |
| DES / 3DES | `symmetric_encrypt(data,'DES',64,'CBC')` or `'3DES'` | Legacy; only when explicitly required |
| Decrypt symmetric | `symmetric_decrypt(envelope,key)` | bytes returned |
| Hash file | `crypto_tools.file_hash(path,'sha512')` | `md5`, `sha1`, `sha256`, `sha512` |
| Hash text | `hash_text('hello','sha256')` | hex string |
| RSA public/private keys | `rsa_keys(2048)` / `rsa_keys(4096)` | returns `(public,private)` |
| RSA encrypt AES key | `rsa_wrap(public,aes_key)` | RSA-OAEP with SHA-256 |
| RSA decrypt AES key | `rsa_unwrap(private,wrapped)` | bytes |
| RSA digital signature | `rsa_sign(data,private,'sha256')` | RSA-PSS; signature base64 |
| RSA verify | `rsa_verify(data,signature,public,'sha256')` | boolean |
| RSA + AES/DES/3DES file | `asymmetric_extra.rsa_hybrid_encrypt(data,public,...)` | Hybrid envelope |
| ECC + AES | `ecc_keypair()`, `ecc_encrypt(data,public)`, `ecc_decrypt(package,private)` | ECDH + HKDF + AES-GCM |
| DH key exchange | `dh_demo()` | Educational finite-field DH |
| ElGamal encryption | `elgamal_keys()`, `elgamal_encrypt(m,pub)`, `elgamal_decrypt(c,pub,x)` | Integer messages, demo |
| ElGamal multiplication | `elgamal_multiply(c1,c2,pub)` | Multiplicative homomorphism |
| ElGamal signature | `elgamal_sign(data,pub,x)` / `elgamal_verify(...)` | Educational |
| Schnorr signature | `schnorr_keys()`, `schnorr_sign(data,pub,x)` | Educational |
| Rabin encrypt/decrypt | `rabin_keys()`, `rabin_encrypt()`, `rabin_decrypt_roots()` | Four roots |
| Paillier encrypt | `pub,priv=paillier_keys()` then `pub.encrypt(amount)` | `phe` package |
| Paillier add encrypted values | `paillier_sum(pub,[c1,c2,...])` | Only final `priv.decrypt(total)` |
| Save encrypted Paillier number | `paillier_pack(cipher)` / `paillier_unpack(pub,obj)` | JSON-safe |
| Keyword search | `searchable.build_index()`, `query()` | HMAC protected index |
| JSON persistence | `storage.load(path)` / `storage.save(path,data)` | Save keys separately |
| Client-server | `network.server_once()` / `client_request()` | Framed JSON over TCP |
| Hex dump | `utils.hex_dump(bytes)` | Useful for decrypted descriptions |
| Timing | `utils.benchmark(lambda: ...,repeats=5)` | Median milliseconds |
| Role permissions | `access.require(role,action)` | Authorization only; login separately |

## Sample combination: RSA + DES + SHA-512 + file

```python
from crypto_tools import rsa_keys, rsa_sign, rsa_verify, hash_bytes
from asymmetric_extra import rsa_hybrid_encrypt, rsa_hybrid_decrypt
from pathlib import Path

public, private = rsa_keys(2048)
data = Path('sample.txt').read_bytes()
package = rsa_hybrid_encrypt(data, public, 'DES', 64, 'CBC')
digest = hash_bytes(data, 'sha512')
signature = rsa_sign(data, private, 'sha512')
recovered = rsa_hybrid_decrypt(package, private)
print('Hash:', digest)
print('Signature valid:', rsa_verify(recovered, signature, public, 'sha512'))
print('Same file:', recovered == data)
```

## Sample combination: AES-192 + MD5 + RSA + Paillier

```python
from crypto_tools import *
public, private = rsa_keys(2048)
ppub, ppriv = paillier_keys()
envelope, aes_key = symmetric_encrypt(b'Grant description','AES',192,'GCM')
amount_cipher = ppub.encrypt(15)
record_hash = hash_bytes(b'canonical record bytes','md5')
signature = rsa_sign(record_hash.encode(), private, 'sha256')
assert rsa_verify(record_hash.encode(), signature, public, 'sha256')
total = paillier_sum(ppub,[amount_cipher,ppub.encrypt(25)])
print('Final sum:',ppriv.decrypt(total))
```

## Where to change things

- **AES key size:** `128`, `192`, `256` (bits) in `symmetric_encrypt`.
- **AES mode:** `'CBC'`, `'CTR'`, `'GCM'`.
- **Hash:** `'md5'`, `'sha1'`, `'sha256'`, `'sha512'`.
- **RSA bits:** `rsa_keys(2048)` or `rsa_keys(4096)`.
- **Input:** text -> `.encode('utf-8')`; file -> `Path(...).read_bytes()`.
- **Output:** decrypted bytes -> `.decode('utf-8')` for text, `.hex()` for hex, `.write_bytes()` for files.
- **Menus:** `universal_menu.py` role handlers, or `grant_portal.py` for a Paillier records scenario.

## Eight critical traps

1. RSA cannot directly encrypt a 1 MB file: encrypt the symmetric session key using RSA.
2. ECDH derives a shared secret; use HKDF and AES to encrypt actual data.
3. Paillier adds **ciphertexts by multiplying**; RSA/ElGamal multiplicatively combine ciphertexts.
4. Paillier returns plaintext arithmetic modulo `n`; avoid overflow of totals.
5. Encrypting the same word with randomized AES/Paillier/RSA-OAEP will not create equal ciphertexts. Use a proper searchable index.
6. Do not regenerate encryption keys on restart if stored records must remain decryptable.
7. Digital signatures authenticate signed bytes only; include IDs, encrypted amounts, timestamps and all relevant fields in canonical signed data.
8. A local timestamp is not a trusted timestamp; splitting a Paillier key is not automatically threshold decryption.
