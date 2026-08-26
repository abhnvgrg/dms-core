"""Structural sanity checks that run before any parser sees an uploaded file.

The OCR, NER and embedding stages are all parsers, and they run over files of
unknown provenance. Malware scanning catches known-bad content; this catches
files that are structurally hostile -- a PDF carrying JavaScript or an auto-run
action -- before they reach anything that would interpret them.

Deliberately implemented as a byte scan rather than a PDF parse: handing the
file to a PDF library to decide whether it is safe to hand to a PDF library
would defeat the point.
"""
import io
import re

# Actions a PDF has no business carrying in an evidence pipeline. /AA is the
# additional-actions dictionary, which is how auto-run is usually smuggled in.
_DANGEROUS_PDF_TOKENS: tuple[tuple[bytes, str], ...] = (
    (b"/JavaScript", "embedded JavaScript"),
    (b"/JS", "embedded JavaScript"),
    (b"/Launch", "launch action"),
    (b"/OpenAction", "auto-executing open action"),
    (b"/AA", "additional-actions dictionary"),
    (b"/EmbeddedFile", "embedded file attachment"),
    (b"/RichMedia", "embedded rich media"),
    (b"/XFA", "XFA form"),
)

MAX_IMAGE_PIXELS = 50_000_000


class FileRejected(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _inspect_pdf(data: bytes) -> None:
    if not data.startswith(b"%PDF-"):
        raise FileRejected("file is not a PDF despite its content type")

    for token, description in _DANGEROUS_PDF_TOKENS:
        if re.search(re.escape(token) + rb"[^A-Za-z]", data):
            raise FileRejected(f"PDF contains {description}")


def _inspect_image(data: bytes, content_type: str) -> None:
    from PIL import Image

    expected = {"image/jpeg": ("JPEG", "MPO"), "image/png": ("PNG",)}[content_type]

    try:
        with Image.open(io.BytesIO(data)) as image:
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            fmt = image.format
            width, height = image.size
    except FileRejected:
        raise
    except Exception as error:
        raise FileRejected(f"image could not be decoded: {error}") from error

    if fmt not in expected:
        raise FileRejected(f"image is {fmt}, which does not match its declared content type")

    if width * height > MAX_IMAGE_PIXELS:
        raise FileRejected("image dimensions exceed the decompression-bomb limit")


def inspect(data: bytes, content_type: str) -> None:
    """Raise FileRejected if the file is structurally unfit to process."""
    if content_type == "application/pdf":
        _inspect_pdf(data)
    elif content_type in ("image/jpeg", "image/png"):
        _inspect_image(data, content_type)
    else:
        raise FileRejected(f"no structural check defined for {content_type}")
