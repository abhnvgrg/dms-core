import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "storage", "keys")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "document_signing_public_key.pem")

_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def verify_signature(digest_hex: str, signature_hex: str) -> bool:
    if not os.path.exists(PUBLIC_KEY_FILE):
        return False

    with open(PUBLIC_KEY_FILE, "rb") as handle:
        public_key = serialization.load_pem_public_key(handle.read())
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            digest_hex.encode("utf-8"),
            _PADDING,
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
