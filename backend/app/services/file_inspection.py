import io
import re

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
    if content_type == "application/pdf":
        _inspect_pdf(data)
    elif content_type in ("image/jpeg", "image/png"):
        _inspect_image(data, content_type)
    else:
        raise FileRejected(f"no structural check defined for {content_type}")
