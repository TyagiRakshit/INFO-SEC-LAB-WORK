# SAMPLE EXAM QUESTION BREAKDOWN

## Q1: Secure Grant Expense Portal

| Requirement | Implementation |
|---|---|
| Researcher enters grant ID, description, amount | `grant_portal.py` researcher menu |
| AES-192 description | `symmetric_encrypt(...,'AES',192,'GCM')` |
| Paillier amount | `ppub.encrypt(amount)` |
| MD5 record | canonical JSON fields -> `hash_bytes(...,'md5')` |
| RSA digital signature | RSA-PSS signature over MD5 hex text, using SHA-256 internally |
| Persist old records | JSON records and key file |
| Reviewer search by ID | dictionary lookup; no plaintext description shown until decrypt |
| Verify MD5 and signature | `verify()` function |
| Hex dump | `hex_dump(symmetric_decrypt(...))` |
| Finance selected encrypted sum | `paillier_sum` of ciphertexts, decrypt final only |
| Invalid/tampered handling | catches common malformed records and rejects bad signatures |
| Role-based menu | role selection; **no authenticated RBAC** |

**Do not overclaim:** MD5 is weak; private keys are stored unencrypted in a local demo file; users choose roles without credentials. No true multi-user secure server.

## Q2: E-voting

| Requirement | Current `voting_demo.py` |
|---|---|
| Ballot with candidate + constituency | Yes |
| SHA-512 hash | Yes |
| AES-256 CBC | Yes; includes HMAC to detect tampering |
| AES key wrapped with RSA-4096 | Yes |
| ElGamal signature | Classroom demonstration |
| Paillier vote encryption | One-hot encrypted votes per candidate, correct approach for tallying |
| Timestamp | Local UTC timestamp only, **not trusted** |
| Server verify and decrypt | Local demonstration, not a separate server process |
| Constituency search | HMAC token, leaks match patterns |
| Time-range search | Not implemented |
| Threshold Paillier decryption | **Not implemented**; single private key |
| Real voter identity and one-vote-per-voter | **Not implemented** |
| Binding of encrypted vote to signed ballot | **Not implemented**; a security gap |
| Real RBAC | **Not implemented** |

**For the exam:** Clearly describe this as a partial demonstration if asked for trusted timestamps, threshold decryption or a fully verifiable election. These require specialized protocols; do not replace them with local clock calls or a single-key decrypt and call them complete.

## Five additional exam scenarios to practice

1. Hospital portal: AES-256 patient notes + RSA signature + SHA-256 + ID search + role menus.
2. Secure document transfer: ECC ECDH + AES-GCM file encryption + SHA-512 hash + socket client/server.
3. Expense calculator: DES-encrypted descriptions + Paillier totals + RSA verification + JSON persistence.
4. Student records: AES-192 CBC + HMAC search tokens + ECDSA signatures + timestamp display.
5. Agency network: RSA-OAEP wrapped AES key + DH demonstration + key expiry/revocation registry + audit log.

For each, check: input validation, menu options, key persistence, invalid signatures, modified ciphertext, and restart behavior.
