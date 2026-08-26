from passlib.context import CryptContext

# Argon2id is the target scheme; bcrypt stays listed so hashes created before
# the switch still verify and get upgraded on the owner's next login.
password_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__type="ID",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4,
)


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_context.verify(password, password_hash)


def needs_rehash(password_hash: str) -> bool:
    return password_context.needs_update(password_hash)
