# Document Authentication System

A simple Python project that signs documents and verifies their authenticity using digital signatures.

## What It Provides

- Integrity: SHA-256 detects document changes.
- Authentication: RSA-PSS verifies the claimed signer.
- Non-repudiation: only the private key holder can create a valid signature.
- No confidentiality: documents are not encrypted because secrecy is not the goal.

## How To Run

```powershell
pip install -r requirements.txt
python Crypto_Project.py
```

## Expected Tests

The program automatically runs four tests:

1. Valid signature: succeeds.
2. Document tampering: fails.
3. Wrong public key: fails.
4. Signature tampering: fails.

## Main Files

- `Crypto_Project.py`: source code.
- `requirements.txt`: dependency list.
- `Document_Authentication_Report.md`: technical report.
- `signed_packages/`: valid signed samples.
- `tampered_packages/`: tampered samples used for failure tests.

Private keys are generated locally in `keys/` and are intentionally ignored by Git.
