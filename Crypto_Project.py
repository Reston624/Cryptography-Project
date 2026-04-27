import os
from datetime import datetime, timezone, timedelta
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey



# Identity + Document Input
SIGNER_NAME         = "Document Signature"
SIGNER_ORGANIZATION = "Cryptography-Course"
SIGNER_COUNTRY      = "EG"
CERT_VALID_DAYS     = 365

DOCUMENT_PATH = "hash.txt"
with open(DOCUMENT_PATH, "rb") as f:
    DOCUMENT_BYTES = f.read()

print("-->Document Authentication System")
print(f"Signer      : {SIGNER_NAME} / {SIGNER_ORGANIZATION} ({SIGNER_COUNTRY})")
print(f"Document    : {DOCUMENT_PATH}")
print(f"Size        : {len(DOCUMENT_BYTES)} bytes")
print()

#Hash the document
document_hash = hashlib.sha256(DOCUMENT_BYTES).digest()

print("-->Document Hashed")
print(f"Hash (hex)  : {hashlib.sha256(DOCUMENT_BYTES).hexdigest()}")
print()


#Generate key pair and sign
private_key = Ed25519PrivateKey.generate()
public_key  = private_key.public_key()
signature   = private_key.sign(document_hash)

print("-->Document Signed")
print(f"Signature   : {signature.hex()}")
print()


# sending the package
package = {
    "document"  : DOCUMENT_BYTES,
    "signature" : signature,
    "public_key": public_key,
}

# receiver-side --> re-hash the received document independently
received_document   = package["document"]
received_signature  = package["signature"]
received_public_key = package["public_key"]

received_hash = hashlib.sha256(received_document).digest()

# verify
try:
    received_public_key.verify(received_signature, received_hash)
    print("✓ Signature valid ")
except Exception as e:
    print("✗ Signature invalid")