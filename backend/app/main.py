import hashlib
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.security import (
    login_user,
    make_token,
    read_token,
    sign_digest,
    check_signature,
    USERS,
)
from app.db import init_db, open_conn
from app.ocr import run_ocr, mask_sensitive_entities

app = FastAPI(title="NyayVault - MVP")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

FILES_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "files")
os.makedirs(FILES_DIR, exist_ok=True)


@app.on_event("startup")
def on_startup():
    init_db()


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    full_name: str


def get_logged_in_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = read_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    username = payload.get("sub")
    user = USERS.get(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.post("/auth/login", response_model=LoginResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = login_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = make_token({"sub": user["username"], "role": user["role"]})
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        role=user["role"],
        full_name=user["full_name"],
    )


@app.get("/auth/me")
def whoami(user: dict = Depends(get_logged_in_user)):
    return {
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
    }


@app.post("/evidence/upload")
async def upload_evidence(
    case_id: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(get_logged_in_user),
):
    raw_bytes = await file.read()

    file_hash = hashlib.sha256(raw_bytes).hexdigest()
    signature = sign_digest(file_hash)

    saved_name = f"{file_hash}_{file.filename}"
    saved_path = os.path.join(FILES_DIR, saved_name)
    with open(saved_path, "wb") as f:
        f.write(raw_bytes)

    ocr_status, extracted_text = run_ocr(raw_bytes, file.content_type or "")
    redacted_text = mask_sensitive_entities(extracted_text) if ocr_status == "ok" else ""

    uploaded_at = datetime.now(timezone.utc).isoformat()

    with open_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO evidence
                (case_id, filename, stored_path, sha256_hash, signature,
                 uploaded_by, uploaded_at, extracted_text, redacted_text, ocr_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                file.filename,
                saved_path,
                file_hash,
                signature,
                user["username"],
                uploaded_at,
                extracted_text,
                redacted_text,
                ocr_status,
            ),
        )
        conn.commit()
        new_id = cur.lastrowid

    return {
        "id": new_id,
        "case_id": case_id,
        "filename": file.filename,
        "sha256_hash": file_hash,
        "signature": signature,
        "uploaded_by": user["username"],
        "uploaded_at": uploaded_at,
        "ocr_status": ocr_status,
        "redacted_text": redacted_text,
    }


@app.get("/evidence")
def list_evidence(user: dict = Depends(get_logged_in_user)):
    with open_conn() as conn:
        rows = conn.execute(
            "SELECT id, case_id, filename, sha256_hash, uploaded_by, uploaded_at, ocr_status "
            "FROM evidence ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: int, user: dict = Depends(get_logged_in_user)):
    with open_conn() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return dict(row)


@app.post("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: int, user: dict = Depends(get_logged_in_user)):
    with open_conn() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    record = dict(row)
    saved_path = record["stored_path"]

    if not os.path.exists(saved_path):
        return {
            "evidence_id": evidence_id,
            "integrity": "FAILED",
            "reason": "File missing from storage",
        }

    with open(saved_path, "rb") as f:
        current_bytes = f.read()
    current_hash = hashlib.sha256(current_bytes).hexdigest()

    hash_match = current_hash == record["sha256_hash"]
    signature_valid = check_signature(record["sha256_hash"], record["signature"])
    integrity_ok = hash_match and signature_valid

    return {
        "evidence_id": evidence_id,
        "filename": record["filename"],
        "original_hash": record["sha256_hash"],
        "recomputed_hash": current_hash,
        "hash_match": hash_match,
        "signature_valid": signature_valid,
        "integrity": "VERIFIED" if integrity_ok else "TAMPERED",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
