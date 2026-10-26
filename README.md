# INFORMATION SECURITY LAB EXAM — OFFLINE TOOLKIT v2

**Scope:** Reusable Python building blocks for Labs 1–8, two sample scenario programs, menu skeleton, networking, storage, tests and exam notes. Intended for permitted classroom preparation and offline exam use. **Not a production security system.**

## 1. Installation (DO THIS BEFORE THE EXAM)

Python 3.10+ recommended. In a terminal with internet access, install:

```bash
python -m pip install pycryptodome phe cryptography
```

For offline installation, download wheels **on a machine with internet**, matching the exam machine's Python version and operating system:

```bash
python -m pip download --dest wheels pycryptodome phe cryptography
```

Copy the `wheels/` directory alongside this toolkit. On the offline machine:

```bash
python -m pip install --no-index --find-links wheels pycryptodome phe cryptography
```

`phe` may require dependencies; `pip download` also fetches them. **Confirm permitted software and local package availability with the lab instructor.** This ZIP does not bundle third-party wheel packages. Python built-ins `hashlib`, `json`, `socket`, `sqlite3`, `secrets` need no installation.

## 2. Directory map

| File | Purpose |
|---|---|
| `crypto_tools.py` | Symmetric AES/DES/3DES, hash, RSA-OAEP/PSS, Paillier, simple ElGamal signing, file encryption |
| `classical.py` | Lab 1: shift, multiplicative, affine, Vigenere, autokey, Playfair, Hill 2x2, brute force |
| `asymmetric_extra.py` | Lab 3/4: RSA hybrid, ECC ECDH+AES, DH, ElGamal encryption/multiplication, Rabin |
| `signatures_extra.py` | Lab 6: Schnorr demo, ECDSA |
| `searchable.py` | Lab 8: HMAC index and encrypted documents |
| `network.py` | Length-framed TCP client/server messages |
| `storage.py` | Atomic JSON persistence and audit log |
| `access.py` | Role authorization and salted password hashing demo |
| `utils.py` | Input validation, hex dump, timestamps, benchmarks |
| `universal_menu.py` | **Editable exam menu skeleton**; placeholder operations clearly marked |
| `grant_portal.py` | Grant question: menu, AES-192, MD5, RSA signature, Paillier, JSON persistence |
| `voting_demo.py` | Partial e-voting example; NOT full real voting protocol |
| `examples/` | File/text hybrid, socket client/server, classical demo |
| `tests/` | Automated standard and crypto checks |
| `docs/EXAM_CHEATSHEET.md` | Which functions to use for which requirement |
| `docs/QUESTION_BREAKDOWN.md` | Breakdown of both sample exam scenarios and missing features |

## 3. Start here

```bash
python examples/classical_demo.py
python examples/mixed_crypto_demo.py
python examples/mixed_crypto_demo.py path/to/your_file.pdf
python grant_portal.py
python voting_demo.py
python universal_menu.py
python -m unittest discover -s tests -v
```

For sockets, use two terminals:

```bash
python examples/socket_server.py
python examples/socket_client.py
```

## 4. Editing the exam question quickly

1. Circle the **entities/fields**: record ID, message, amount, document, timestamp, voter, patient.
2. Circle the **operations**: encrypt, hash, sign, verify, add ciphertexts, search, send, save.
3. Circle the **algorithm constraints**: AES-192/CBC, RSA-4096, SHA-512, Paillier, etc.
4. Circle the **roles**: who submits, who reviews, who decrypts, who tallies.
5. Start with `universal_menu.py` for a new scenario or `grant_portal.py` if it has encrypted amounts.
6. Replace only the fields, selected algorithms and role functions. Keep cryptographic functions in modules.
7. Use JSON-compatible ciphertext envelopes (base64 strings) and **persist keys**. Regenerating keys on restart makes previous records unreadable.
8. Test a successful record, a tampered record, invalid input, missing ID, duplicate ID, restart and aggregation.

## 5. Known limitations and precise security claims

- `grant_portal.py`: role selection is NOT user authentication. Key file is **plaintext** on disk. MD5 is collision-broken; requested by sample exam. RSA-PSS signs the MD5 digest *text* using SHA-256; this is not RSA-PSS-with-MD5 directly. Paillier final total must stay within plaintext range and data integrity is checked before aggregation.
- `voting_demo.py`: uses a **local clock**, not a trusted timestamp authority; has **single-authority** Paillier decryption, NOT threshold decryption. It does not authenticate real voters or enforce one vote per voter, and is NOT suitable for real elections. The separate encrypted vote vector is not cryptographically bound to the signed ballot, so it is **not tamper-proof**. It should not be described as meeting all e-voting requirements.
- `universal_menu.py` is a **skeleton** with intentional plaintext placeholders; replace them before claiming confidentiality/homomorphic aggregation.
- `classical.py` preserves only A–Z letters, strips spaces/punctuation, and Playfair may insert filler characters. It is for classical-cipher exercises only.
- `asymmetric_extra.py` ElGamal, Rabin, DH and `signatures_extra.py` Schnorr are educational constructions; do not use for real sensitive data. Rabin decryption produces four candidate roots.
- `crypto_tools.py` AES-GCM uses authenticated encryption. CBC and CTR modes use an additional HMAC; DES/3DES are legacy. RSA-OAEP wraps only short session keys, not large files. RSA-PSS signs data digests using an approved library implementation.
- `searchable.py` uses deterministic HMAC keyword tokens and reveals equality/search/access patterns. It is a classroom SSE-style design, not a formally analyzed SSE protocol.
- **Ordinary Paillier encryption does not provide direct equality-search or threshold decryption.** The Lab 8 sample's decrypt-to-compare is not true server-side privacy-preserving PKSE.
- Key management, identity verification, timestamp authority and threshold decryption require additional infrastructure/protocols. A single local script cannot truthfully claim those capabilities without implementing them.

## 6. How to run tests

```bash
python -m compileall -q .
python -m unittest discover -s tests -v
```

The `test_standard.py` tests need only Python built-ins. `test_crypto.py` requires all three external libraries. On the exam computer, run these tests **before** the exam begins if allowed.

## 7. If an import fails offline

- `ModuleNotFoundError: No module named 'Crypto'` -> install `pycryptodome` (not `crypto`).
- `ModuleNotFoundError: No module named 'phe'` -> install `phe`.
- `ModuleNotFoundError: No module named 'cryptography'` -> install `cryptography`.
- If the machine disallows package installation, ask the instructor what libraries are preinstalled. Do not assume packages can be fetched without internet.

## 8. Critical exam checklist

- [ ] All menus work; **0 exits**; invalid options handled.
- [ ] Input constraints checked; duplicate IDs rejected.
- [ ] File persists and keys persist after restart.
- [ ] Correct key size/mode/hash algorithm as required.
- [ ] Sign/verify same canonical bytes, including every field that must be protected.
- [ ] Verify before accepting records for totals.
- [ ] Homomorphic aggregate is computed from ciphertexts, and only the final sum decrypted.
- [ ] Decryption shows original text or bytes and optionally hex dump.
- [ ] Tamper test visibly fails.
- [ ] Claims match implementation (no fake trusted timestamp, threshold decryption, or authentication).
