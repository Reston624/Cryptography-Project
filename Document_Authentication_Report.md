# Document Authentication System Using Digital Signatures

## 1. System Architecture

This project implements a simple document authentication system. The system signs a document with a private RSA key and later verifies it with the matching public RSA key.

The project contains four main parts:

- Hashing module: computes a SHA-256 hash of the document.
- Signature module: signs the document hash using RSA-PSS and the signer's private key.
- Verification module: recomputes the hash and verifies the signature using the signer's public key.
- Package module: stores the document, signature, signer ID, timestamp, and algorithm information in a readable JSON file.

The document remains plaintext. The goal is authentication and integrity, not secrecy.

## 2. Cryptographic Design Choices

### Hash Function

The system uses SHA-256. SHA-256 produces a fixed 32-byte digest for any document size. Hashing is needed before signing because signing large files directly is inefficient. Instead of signing the whole file, the system signs the hash that represents the file content.

If even one bit of the document changes, the SHA-256 hash changes. This allows the system to detect tampering.

### Digital Signature Algorithm

The system uses RSA-PSS with 2048-bit RSA keys. RSA is asymmetric, meaning each user has:

- A private key used only for signing.
- A public key used only for verification.

RSA-PSS is used because it is a modern secure padding mode for RSA signatures.

### Key Management

The program generates a separate key pair for each user and stores the keys in the `keys` folder.

Public keys can be shared with other users because they are only used for verification. Private keys must stay secret. If a private key is compromised, signatures made by that key can no longer be trusted, and the user should generate a new key pair and tell others to reject the old public key.

This project does not implement a full PKI or certificate authority. It assumes the verifier already has the correct public key for the signer.

## 3. Threat Model

The attacker may:

- Modify the document.
- Replace the document.
- Attempt to forge a signature.
- Claim false authorship.
- Modify the signature file.

The attacker cannot:

- Access the private signing key.

## 4. Security Guarantees

| Security Property | Provided? | How |
| --- | --- | --- |
| Integrity | Yes | SHA-256 hash changes when the document changes |
| Authentication | Yes | RSA signature verifies the claimed signer |
| Non-repudiation | Yes | Only the private key holder can create a valid signature |
| Confidentiality | No | The document is not encrypted |

Encryption is not required because the project is about proving that a document is authentic and unchanged. The document can be public and still have a valid digital signature.

## 5. Signing Workflow

Given a document `D`:

1. Read the document bytes.
2. Compute `h = SHA256(D)`.
3. Generate `sig = Sign(h, private_key)`.
4. Save a signed package containing:
   - Document data
   - Signature
   - Signer ID
   - Hash algorithm
   - Signature algorithm
   - Timestamp

## 6. Verification Workflow

Given a signed package:

1. Extract the document and signature.
2. Recompute `h' = SHA256(D)`.
3. Load the signer's public key.
4. Verify the signature against `h'`.
5. Accept the document only if verification succeeds.

Verification fails if:

- The document is changed.
- The wrong public key is used.
- The signature is modified.
- Required package fields are missing.

## 7. Signed Document Format

The project uses JSON because it is easy to inspect during a demo.

Main fields:

- `format`: package version.
- `signer_id`: identifies which public key should be used.
- `document_base64`: plaintext document bytes encoded for JSON.
- `document_sha256_hex`: SHA-256 hash of the document.
- `signature_base64`: RSA-PSS signature encoded for JSON.
- `algorithm_info`: hash, signature algorithm, key size, and public key file.
- `timestamp_utc`: time when the package was created.

The timestamp is included for information only. It is not trusted like a timestamp from a real timestamp authority.

## 8. Experiments and Test Cases

The program automatically runs the required tests:

1. Valid signature: the original document is verified with the correct public key, so verification succeeds.
2. Document tampering: the document content is changed inside the package, so verification fails.
3. Wrong public key: the package is verified with another user's public key, so verification fails.
4. Signature tampering: one bit of the signature is changed, so verification fails.

## 9. Limitations

This project is intentionally simple for learning and presentation purposes.

- Private keys are not password protected.
- No full certificate authority or revocation list is implemented.
- Timestamp trust is not implemented.
- The JSON package is designed for readability, not storage efficiency.
- The system authenticates documents but does not encrypt them.

## 10. How to Run

Install the dependency once:

```powershell
pip install -r requirements.txt
```

Run the project:

```powershell
python Crypto_Project.py
```

The program creates keys, valid signed samples, tampered samples, and prints the verification results.
