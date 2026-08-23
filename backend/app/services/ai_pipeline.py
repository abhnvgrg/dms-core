import pytesseract
from PIL import Image
import io

_nlp_model = None


def _load_nlp_model():
    global _nlp_model
    if _nlp_model is None:
        import spacy
        _nlp_model = spacy.load("en_core_web_sm")
    return _nlp_model


def extract_text(file_bytes: bytes, content_type: str) -> tuple[str, str | None]:
    if not content_type.startswith("image/"):
        return "unsupported", None
    try:
        image = Image.open(io.BytesIO(file_bytes))
        text = pytesseract.image_to_string(image)
        return "ok", text.strip()
    except Exception as e:
        return "error", str(e)


ENTITY_TYPES_TO_MASK = {"PERSON", "GPE", "LOC", "ORG"}


def redact_pii(text: str) -> str:
    if not text:
        return ""
    nlp = _load_nlp_model()
    doc = nlp(text)
    redacted = text
    entities = sorted(doc.ents, key=lambda e: len(e.text), reverse=True)
    for ent in entities:
        if ent.label_ in ENTITY_TYPES_TO_MASK:
            redacted = redacted.replace(ent.text, f"[REDACTED-{ent.label_}]")
    return redacted


_embedding_model = None


def _load_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        from sentence_transformers import SentenceTransformer
        _embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedding_model


def generate_embedding(text: str) -> list[float] | None:
    if not text:
        return None
    model = _load_embedding_model()
    vector = model.encode(text)
    return vector.tolist()