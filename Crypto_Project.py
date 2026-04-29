import os
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import datetime as a


# IDENTITY
SIGNER_NAME         = "Team-Project"
SIGNER_ORGANIZATION = "Cryptography-Course"
SIGNER_COUNTRY      = "EG"


# User picks the file
DOCUMENT_PATH = input("Enter document path: ").strip()

if not os.path.exists(DOCUMENT_PATH):
    print("✗ File not found")
    exit()

with open(DOCUMENT_PATH, "rb") as f:
    DOCUMENT_BYTES = f.read()

print()
print("-->Document Authentication System")
print(f"Signer      : {SIGNER_NAME} / {SIGNER_ORGANIZATION} ({SIGNER_COUNTRY})")
print(f"Document    : {DOCUMENT_PATH}")
print(f"Size        : {len(DOCUMENT_BYTES)} bytes")
print()

# Hash original content only
# original file is never touched
document_hash = hashlib.sha256(DOCUMENT_BYTES).digest()
document_hex  = hashlib.sha256(DOCUMENT_BYTES).hexdigest()

print("-->Document Hashed")
print(f"Hash (hex)  : {document_hex}")
print()

#Generate key pair and sign
private_key      = Ed25519PrivateKey.generate()
public_key       = private_key.public_key()
signature        = private_key.sign(document_hash)

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print("-->Document Signed")
print(f"Signature   : {signature.hex()}")
print()


# Write sidecar .sig file
sig_path = DOCUMENT_PATH + ".sig"

with open(sig_path, "w") as f:
    f.write(f"SIGNER: {SIGNER_NAME}\n")
    f.write(f"ORGANIZATION: {SIGNER_ORGANIZATION}\n")
    f.write(f"COUNTRY: {SIGNER_COUNTRY}\n")
    f.write(f"FILE: {os.path.basename(DOCUMENT_PATH)}\n")
    f.write(f"HASH: {document_hex}\n")
    f.write(f"SIGNATURE: {base64.b64encode(signature).decode()}\n")
    f.write(f"PUBLIC_KEY: {base64.b64encode(public_key_bytes).decode()}\n")
    f.write(f"SIGNED_AT: {a.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

print("-->Sidecar Signature File Created")
print(f"Saved to    : {sig_path}")
print()

# Verify
# read original file + .sig file separately
# load original file — untouched

with open(DOCUMENT_PATH, "rb") as f:
    original_bytes = f.read()

# load signature file
if not os.path.exists(sig_path):
    print("✗ No .sig file found")
    exit()

with open(sig_path, "r") as f:
    block_data = {}
    for line in f:
        if ":" in line:
            key, value = line.split(":", 1)
            block_data[key.strip()] = value.strip()

# extract fields
extracted_signature  = base64.b64decode(block_data["SIGNATURE"])
extracted_public_key = base64.b64decode(block_data["PUBLIC_KEY"])
extracted_signer     = block_data["SIGNER"]
extracted_hash       = block_data["HASH"]
extracted_signed_at  = block_data["SIGNED_AT"]

# reconstruct public key object
public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(extracted_public_key)

# re-hash original file independently
recomputed_hash = hashlib.sha256(original_bytes).digest()
recomputed_hex  = hashlib.sha256(original_bytes).hexdigest()


# Print verification report
print("-->Verification Report")
print(f"File        : {DOCUMENT_PATH}")
print(f"Signer      : {extracted_signer}")
print(f"Signed at   : {extracted_signed_at}")
print(f"Recorded hash  : {extracted_hash}")
print(f"Recomputed hash: {recomputed_hex}")
print(f"Hash match     : {'✓' if recomputed_hex == extracted_hash else '✗'}")
print()

# verify signature
try:
    public_key_obj.verify(extracted_signature, recomputed_hash)
    print("✓ Signature valid — document is authentic and untampered")
except Exception as e:
    print("✗ Signature invalid — document may have been tampered with")