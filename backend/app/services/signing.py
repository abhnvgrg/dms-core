import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "storage", "keys")
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "document_signing_private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "document_signing_public_key.pem")

_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _ensure_keys_exist() -> None:
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        return

    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIVATE_KEY_FILE, "wb") as handle:
        handle.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as handle:
        handle.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def sign_digest(digest_hex: str) -> str:
    _ensure_keys_exist()
    with open(PRIVATE_KEY_FILE, "rb") as handle:
        private_key = serialization.load_pem_private_key(handle.read(), password=None)
    signature = private_key.sign(digest_hex.encode("utf-8"), _PADDING, hashes.SHA256())
    return signature.hex()


def verify_signature(digest_hex: str, signature_hex: str) -> bool:
    _ensure_keys_exist()
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
