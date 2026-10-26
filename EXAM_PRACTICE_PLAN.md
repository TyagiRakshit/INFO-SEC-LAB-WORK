# Two-hour exam rehearsal

## 0–10 minutes: Parse the question

Make a table with columns: field, protection, algorithm, who can operate, storage. Underline the mandatory menu requirement. Circle key lengths and modes.

## 10–25 minutes: Build menus and data model

Start from `universal_menu.py` or `grant_portal.py`. Add all required menu options. Implement persistent storage and key loading before adding records.

## 25–65 minutes: Cryptography

Wire the symmetric encrypt/decrypt, RSA wrapping/signatures, hashes, Paillier operations, and search tokens as needed. Do not reimplement standard cryptography by hand unless the question specifically asks for that.

## 65–95 minutes: Role workflows

Submit, list, search, verify, decrypt, aggregate, export. Ensure signed bytes are canonical and all relevant fields are signed.

## 95–115 minutes: Tests

1. Valid submit -> list -> verify -> decrypt.
2. Restart -> list previous record -> decrypt.
3. Invalid amount -> graceful error.
4. Duplicate ID -> rejected.
5. Modify saved ciphertext -> integrity/signature failure.
6. Select two amounts -> encrypted sum -> correct final total.
7. Search existing/nonexistent ID.
8. Wrong role -> denied (if authentication and permissions implemented).

## 115–120 minutes: Demonstration

Keep terminal output readable. Show the menu, ciphertext, digest, signature verification, decrypted result and final encrypted aggregate. Avoid dumping private keys.

## Memorize this architecture

```text
INPUT -> VALIDATE -> ENCRYPT -> HASH/SIGN -> SAVE
                         |
                         v
SEARCH -> LOAD -> VERIFY -> DECRYPT AUTHORIZED FIELDS
                         |
                         v
                 AGGREGATE CIPHERTEXTS
                         |
                         v
                 DECRYPT FINAL TOTAL
```
