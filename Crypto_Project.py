import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


# =========================
# Simple Project Settings
# =========================

BASE_DIR = Path(__file__).resolve().parent

KEYS_DIR = BASE_DIR / "keys"
DOCUMENTS_DIR = BASE_DIR / "documents"
SIGNED_DIR = BASE_DIR / "signed_packages"
TAMPERED_DIR = BASE_DIR / "tampered_packages"

DOCUMENT_PATH = BASE_DIR / "hash.txt"

SIGNER_ID = "ehab"
SIGNER_NAME = "Ehab Abdelaziz"
SIGNER_ORGANIZATION = "Security Course Project"
SIGNER_COUNTRY = "EG"
CERT_VALID_DAYS = 365

OTHER_SIGNER_ID = "wrong_user"


# =========================
# Utility Functions
# =========================

def ensure_folders():
    """Create the simple folder structure used by the demo."""
    for folder in [KEYS_DIR, DOCUMENTS_DIR, SIGNED_DIR, TAMPERED_DIR]:
        folder.mkdir(exist_ok=True)


def sha256_bytes(data):
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def b64_encode(data):
    return base64.b64encode(data).decode("utf-8")


def b64_decode(text):
    return base64.b64decode(text.encode("utf-8"))


# =========================
# Key Management
# =========================

def private_key_path(user_id):
    return KEYS_DIR / f"{user_id}_private_key.pem"


def public_key_path(user_id):
    return KEYS_DIR / f"{user_id}_public_key.pem"


def generate_key_pair(user_id):
    """Generate one RSA key pair for one user if it does not already exist."""
    priv_path = private_key_path(user_id)
    pub_path = public_key_path(user_id)

    if priv_path.exists() and pub_path.exists():
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(user_id):
    return serialization.load_pem_private_key(
        private_key_path(user_id).read_bytes(),
        password=None,
    )


def load_public_key(user_id):
    return serialization.load_pem_public_key(public_key_path(user_id).read_bytes())


# =========================
# Signing and Verification
# =========================

def sign_hash(document_hash, private_key):
    return private_key.sign(
        document_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )


def verify_hash_signature(document_hash, signature, public_key):
    try:
        public_key.verify(
            signature,
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False


def sign_document(document_path, signer_id, output_path):
    document_bytes = Path(document_path).read_bytes()
    document_hash = sha256_bytes(document_bytes)
    signature = sign_hash(document_hash, load_private_key(signer_id))

    package = {
        "format": "SimpleSignedDocument-v1",
        "signer_id": signer_id,
        "signer_name": SIGNER_NAME,
        "organization": SIGNER_ORGANIZATION,
        "country": SIGNER_COUNTRY,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "certificate_valid_days": CERT_VALID_DAYS,
        "document_name": Path(document_path).name,
        "document_base64": b64_encode(document_bytes),
        "document_sha256_hex": sha256_hex(document_bytes),
        "signature_base64": b64_encode(signature),
        "algorithm_info": {
            "hash": "SHA-256",
            "signature": "RSA-PSS",
            "rsa_key_size": 2048,
            "public_key_file": public_key_path(signer_id).name,
        },
    }

    Path(output_path).write_text(json.dumps(package, indent=2), encoding="utf-8")
    return output_path


def verify_package(package_path, public_key_user_id=None):
    try:
        package = json.loads(Path(package_path).read_text(encoding="utf-8"))

        required_fields = [
            "signer_id",
            "document_base64",
            "document_sha256_hex",
            "signature_base64",
        ]
        for field in required_fields:
            if field not in package:
                return False, f"Rejected: missing field '{field}'"

        document_bytes = b64_decode(package["document_base64"])
        signature = b64_decode(package["signature_base64"])
        recomputed_hash = sha256_bytes(document_bytes)
        recomputed_hash_hex = recomputed_hash.hex()

        if recomputed_hash_hex != package["document_sha256_hex"]:
            return False, "Rejected: document hash does not match package metadata"

        user_id = public_key_user_id or package["signer_id"]
        public_key = load_public_key(user_id)

        if verify_hash_signature(recomputed_hash, signature, public_key):
            return True, "Accepted: signature is valid and document is unchanged"

        return False, "Rejected: invalid signature"

    except (OSError, json.JSONDecodeError, ValueError) as error:
        return False, f"Rejected: invalid package ({error})"


# =========================
# Demo Data and Test Cases
# =========================

def create_demo_documents():
    if not DOCUMENT_PATH.exists():
        DOCUMENT_PATH.write_text(
            "This is the original document used for digital signature testing.\n",
            encoding="utf-8",
        )

    second_doc = DOCUMENTS_DIR / "course_certificate.txt"
    if not second_doc.exists():
        second_doc.write_text(
            "Student: Security Course Team\nResult: Document authentication demo passed.\n",
            encoding="utf-8",
        )

    return [DOCUMENT_PATH, second_doc]


def tamper_document_inside_package(valid_package_path, tampered_package_path):
    package = json.loads(Path(valid_package_path).read_text(encoding="utf-8"))
    document_bytes = b64_decode(package["document_base64"])

    # Change one byte/character but keep the old hash and signature.
    package["document_base64"] = b64_encode(document_bytes + b" tampered")

    Path(tampered_package_path).write_text(json.dumps(package, indent=2), encoding="utf-8")


def tamper_signature_inside_package(valid_package_path, tampered_package_path):
    package = json.loads(Path(valid_package_path).read_text(encoding="utf-8"))
    signature = bytearray(b64_decode(package["signature_base64"]))
    signature[0] = signature[0] ^ 1
    package["signature_base64"] = b64_encode(bytes(signature))

    Path(tampered_package_path).write_text(json.dumps(package, indent=2), encoding="utf-8")


def print_result(title, package_path, public_key_user_id=None):
    valid, message = verify_package(package_path, public_key_user_id)
    status = "PASS" if valid else "FAIL"
    print(f"{title}: {status} - {message}")


def run_demo():
    ensure_folders()
    generate_key_pair(SIGNER_ID)
    generate_key_pair(OTHER_SIGNER_ID)

    documents = create_demo_documents()

    signed_hash = SIGNED_DIR / "valid_hash_document.signed.json"
    signed_certificate = SIGNED_DIR / "valid_course_certificate.signed.json"
    tampered_document = TAMPERED_DIR / "tampered_document.signed.json"
    tampered_signature = TAMPERED_DIR / "tampered_signature.signed.json"

    sign_document(documents[0], SIGNER_ID, signed_hash)
    sign_document(documents[1], SIGNER_ID, signed_certificate)
    tamper_document_inside_package(signed_hash, tampered_document)
    tamper_signature_inside_package(signed_hash, tampered_signature)

    document_bytes = documents[0].read_bytes()

    print("=== Document Authentication System Using Digital Signatures ===")
    print(f"Signer      : {SIGNER_NAME} / {SIGNER_ORGANIZATION} ({SIGNER_COUNTRY})")
    print(f"Document    : {documents[0].name}")
    print(f"Size        : {len(document_bytes)} bytes")
    print(f"Cert valid  : {CERT_VALID_DAYS} days from today")
    print(f"Hash (hex)  : {sha256_hex(document_bytes)}")
    print()

    print("=== Test Cases ===")
    print_result("Test 1 - Valid Signature", signed_hash)
    print_result("Test 2 - Document Tampering", tampered_document)
    print_result("Test 3 - Wrong Public Key", signed_hash, OTHER_SIGNER_ID)
    print_result("Test 4 - Signature Tampering", tampered_signature)
    print()

    print("Created files:")
    print(f"- Keys: {KEYS_DIR}")
    print(f"- Valid signed samples: {SIGNED_DIR}")
    print(f"- Tampered samples: {TAMPERED_DIR}")
    print()
    print("Run again anytime with: python Crypto_Project.py")


if __name__ == "__main__":
    run_demo()
