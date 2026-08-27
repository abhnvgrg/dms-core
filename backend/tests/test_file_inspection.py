from __future__ import annotations

import io

import pytest
from PIL import Image

from app.services.file_inspection import FileRejected, inspect


def pdf(body: bytes = b"") -> bytes:
    return b"%PDF-1.7\n" + body + b"\n%%EOF"


def image_bytes(fmt: str = "PNG", size: tuple[int, int] = (64, 64)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, (120, 120, 120)).save(buffer, format=fmt)
    return buffer.getvalue()


def test_a_plain_pdf_is_accepted():
    inspect(pdf(b"/Type /Catalog"), "application/pdf")


def test_something_that_is_not_a_pdf_is_rejected():
    with pytest.raises(FileRejected, match="not a PDF"):
        inspect(b"MZ\x90\x00 this is an executable", "application/pdf")


@pytest.mark.parametrize(
    "token,description",
    [
        (b"/JavaScript ", "JavaScript"),
        (b"/JS ", "JavaScript"),
        (b"/Launch ", "launch action"),
        (b"/OpenAction ", "auto-executing open action"),
        (b"/AA ", "additional-actions"),
        (b"/EmbeddedFile ", "embedded file"),
        (b"/RichMedia ", "rich media"),
        (b"/XFA ", "XFA form"),
    ],
)
def test_active_pdf_content_is_rejected(token, description):
    with pytest.raises(FileRejected):
        inspect(pdf(token), "application/pdf")


def test_the_rejection_names_what_was_found():
    with pytest.raises(FileRejected) as raised:
        inspect(pdf(b"/Launch "), "application/pdf")

    assert "launch action" in raised.value.reason


def test_a_token_that_is_only_a_prefix_is_not_a_false_positive():
    inspect(pdf(b"/JavaScriptable"), "application/pdf")


def test_a_valid_png_is_accepted():
    inspect(image_bytes("PNG"), "image/png")


def test_a_valid_jpeg_is_accepted():
    inspect(image_bytes("JPEG"), "image/jpeg")


def test_a_png_declared_as_a_jpeg_is_rejected():
    with pytest.raises(FileRejected, match="does not match its declared content type"):
        inspect(image_bytes("PNG"), "image/jpeg")


def test_a_jpeg_declared_as_a_png_is_rejected():
    with pytest.raises(FileRejected, match="does not match its declared content type"):
        inspect(image_bytes("JPEG"), "image/png")


def test_a_corrupt_image_is_rejected():
    with pytest.raises(FileRejected, match="could not be decoded"):
        inspect(b"\x89PNG\r\n\x1a\n" + b"garbage" * 20, "image/png")


def test_an_empty_payload_is_rejected():
    with pytest.raises(FileRejected):
        inspect(b"", "image/png")


def test_a_pdf_renamed_as_an_image_is_rejected():
    with pytest.raises(FileRejected):
        inspect(pdf(), "image/png")


def test_a_decompression_bomb_is_rejected(monkeypatch):
    from app.services import file_inspection

    monkeypatch.setattr(file_inspection, "MAX_IMAGE_PIXELS", 1000)

    with pytest.raises(FileRejected, match="decompression-bomb"):
        file_inspection.inspect(image_bytes("PNG", (64, 64)), "image/png")


def test_an_image_inside_the_pixel_limit_is_accepted(monkeypatch):
    from app.services import file_inspection

    monkeypatch.setattr(file_inspection, "MAX_IMAGE_PIXELS", 1_000_000)

    file_inspection.inspect(image_bytes("PNG", (64, 64)), "image/png")
