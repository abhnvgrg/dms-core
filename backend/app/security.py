import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

JWT_SECRET = "sih-demo-secret-change-in-prod"
JWT_ALGO = "HS256"
TOKEN_LIFETIME_MIN = 60 * 8


def hash_password(plain):
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain, hashed):
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


USERS = {
    "officer1": {
        "username": "officer1",
        "full_name": "Investigating Officer Sharma",
        "role": "officer",
        "password_hash": hash_password("officer123"),
    },
    "admin1": {
        "username": "admin1",
        "full_name": "Admin Verma",
        "role": "admin",
        "password_hash": hash_password("admin123"),
    },
}


def login_user(username, password):
    user = USERS.get(username)
    if not user or not check_password(password, user["password_hash"]):
        return None
    return user


def make_token(payload, minutes=TOKEN_LIFETIME_MIN):
    data = payload.copy()
    data["exp"] = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)


def read_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError:
        return None


KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "keys")
os.makedirs(KEYS_DIR, exist_ok=True)
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "demo_private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "demo_public_key.pem")


def ensure_keys_exist():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        return
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    pub = priv.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


ensure_keys_exist()


def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_digest(digest_hex):
    key = load_private_key()
    sig = key.sign(
        digest_hex.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return sig.hex()


def check_signature(digest_hex, signature_hex):
    key = load_public_key()
    try:
        key.verify(
            bytes.fromhex(signature_hex),
            digest_hex.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
