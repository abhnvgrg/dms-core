from PIL import Image
import io

_nlp_model = None


def load_nlp_model():
    global _nlp_model
    if _nlp_model is None:
        import spacy
        _nlp_model = spacy.load("en_core_web_sm")
    return _nlp_model


def run_ocr(file_bytes, content_type):
    if not content_type.startswith("image/"):
        return "unsupported", ""
    try:
        import pytesseract
        img = Image.open(io.BytesIO(file_bytes))
        text = pytesseract.image_to_string(img)
        return "ok", text.strip()
    except Exception as e:
        return "error", f"OCR failed: {e}"


ENTITY_TYPES_TO_MASK = {"PERSON", "GPE", "LOC", "ORG"}


def mask_sensitive_entities(text):
    if not text:
        return ""
    try:
        nlp = load_nlp_model()
        doc = nlp(text)
        masked = text
        entities = sorted(doc.ents, key=lambda e: len(e.text), reverse=True)
        for ent in entities:
            if ent.label_ in ENTITY_TYPES_TO_MASK:
                masked = masked.replace(ent.text, f"[REDACTED-{ent.label_}]")
        return masked
    except Exception as e:
        return f"[PII redaction unavailable: {e}]\n\n{text}"
