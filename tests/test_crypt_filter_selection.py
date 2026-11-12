"""Regression coverage for Crypt Filter selection (PDF 1.7 §7.6.2 / §7.4.10).

These tests build tiny, fully controlled V4/R4 encrypted PDFs in memory so the
exact Crypt Filter that pypdf selects for streams (StmF), strings (StrF) and
embedded-file streams (EFF) can be observed deterministically. They pin the
current behaviour, including the limitation that the EFF slot is computed but
never actually used when decrypting embedded-file streams.
"""
from __future__ import annotations

import hashlib
import re
import zlib
from io import BytesIO

import pytest

from pypdf import PdfReader
from pypdf._crypt_providers import CryptAES, CryptIdentity, CryptRC4
from pypdf._encryption import Encryption
from pypdf.generic import IndirectObject

PASSWORD = "asdfzxcv"
ID1 = b"0123456789abcdef"
P_PERMS = -4

PAGE_TEXT = b"BT /F1 18 Tf 72 700 Td (audit page) Tj ET\n"
ATTACH_PLAIN = b"PLAIN-ATTACHMENT uncompressed payload.\n" * 6
ATTACH_FLATE = b"FLATE-ATTACHMENT compressed payload.\n" * 10
INFO_TITLE = "Document title"

CLASS_OF = {CryptRC4: "CryptRC4", CryptAES: "CryptAES", CryptIdentity: "CryptIdentity"}


def _encryption() -> Encryption:
    enc = Encryption(
        V=4, R=4, Length=128, P=P_PERMS, EncryptMetadata=True,
        first_id_entry=ID1, StmF="/V2", StrF="/V2", EFF="/V2",
        values=None, entry=None,  # type: ignore[arg-type]
    )
    enc.compute_values_v4(PASSWORD.encode(), PASSWORD.encode())
    return enc


def _keys(file_key: bytes, idnum: int) -> tuple[bytes, bytes]:
    n = len(file_key)
    base = hashlib.md5(file_key[:n] + idnum.to_bytes(3, "little") + (0).to_bytes(2, "little"))
    rc4_key = base.digest()[: min(n + 5, 16)]
    base.update(b"sAlT")
    return rc4_key, base.digest()[: min(n + 5, 16)]


def _crypt(method: str, file_key: bytes, idnum: int):
    rc4_key, aes_key = _keys(file_key, idnum)
    if method == "/AESV2":
        return CryptAES(aes_key)
    if method == "/Identity":
        return CryptIdentity()
    return CryptRC4(rc4_key)


def _enc(data: bytes, method: str, file_key: bytes, idnum: int) -> bytes:
    return _crypt(method, file_key, idnum).encrypt(data)


def _hexstr(data: bytes) -> bytes:
    return b"<" + data.hex().encode() + b">"


def _build_pdf(stm_label: str, str_label: str, eff_label: str,
               m_stm: str, m_str: str, m_eff: str) -> bytes:
    """Build a PDF; labels are the advertised /CFM, m_* the real protection."""
    enc = _encryption()
    key = enc._key
    assert key is not None

    page_ct = _enc(zlib.compress(PAGE_TEXT), m_stm, key, 4)
    ef7_ct = _enc(ATTACH_PLAIN, m_eff, key, 7)
    ef8_ct = _enc(zlib.compress(ATTACH_FLATE), m_eff, key, 8)
    title_ct = _hexstr(_enc(INFO_TITLE.encode(), m_str, key, 10))

    label_to_cf = {"/V2": ("/RC4CF", "/V2"), "/AESV2": ("/AESCF", "/AESV2"),
                   "/Identity": ("/Identity", "/Identity"),
                   "/Bogus": ("/BogusCF", "/Bogus"), "/None": ("/NoneCF", "/None")}
    route = {m: label_to_cf[m][0] for m in (stm_label, str_label, eff_label)}
    cf_bodies = []
    for m in dict.fromkeys((stm_label, str_label, eff_label)):
        if m == "/Identity":
            continue
        cf_name, cfm = label_to_cf[m]
        cf_bodies.append(b"%s << /AuthEvent /DocOpen /CFM %s /Length 16 >>"
                         % (cf_name.encode(), cfm.encode()))
    encrypt = b" ".join([
        b"<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4",
        b"/O <%s>" % enc.values.O.hex().encode(),
        b"/U <%s>" % enc.values.U.hex().encode(),
        b"/CF << %s >>" % b" ".join(cf_bodies),
        b"/StmF %s /StrF %s /EFF %s" % (
            route[stm_label].encode(), route[str_label].encode(), route[eff_label].encode()),
        b">>",
    ])

    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 5 0 R >> >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 12 0 R >> >> /Contents 4 0 R >>"),
        4: b"<< /Length %d /Filter /FlateDecode >>" % len(page_ct),
        5: (b"<< /Names [" + _hexstr(_enc(b"plain.txt", m_str, key, 5)) + b" 6 0 R "
            + _hexstr(_enc(b"flate.bin", m_str, key, 5)) + b" 11 0 R] >>"),
        6: (b"<< /Type /Filespec /F " + _hexstr(_enc(b"plain.txt", m_str, key, 6))
            + b" /UF " + _hexstr(_enc(b"plain.txt", m_str, key, 6))
            + b" /EF << /F 7 0 R /UF 7 0 R >> >>"),
        7: b"<< /Type /EmbeddedFile /Subtype /octet-stream /Length %d >>" % len(ef7_ct),
        8: b"<< /Type /EmbeddedFile /Filter /FlateDecode /Length %d >>" % len(ef8_ct),
        10: b"<< /Title %s >>" % title_ct,
        11: (b"<< /Type /Filespec /F " + _hexstr(_enc(b"flate.bin", m_str, key, 11))
             + b" /UF " + _hexstr(_enc(b"flate.bin", m_str, key, 11))
             + b" /EF << /F 8 0 R /UF 8 0 R >> >>"),
        12: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    streams = {4: page_ct, 7: ef7_ct, 8: ef8_ct}

    out = bytearray(b"%PDF-1.7\n")
    offsets: dict[int, int] = {}
    for idnum in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]:
        offsets[idnum] = len(out)
        if idnum == 9:
            out += b"9 0 obj\n" + encrypt + b"\nendobj\n"
            continue
        out += f"{idnum} 0 obj\n".encode() + objs[idnum] + b"\n"
        if idnum in streams:
            out += b"stream\n" + streams[idnum] + b"\nendstream\n"
        out += b"endobj\n"
    xref = len(out)
    out += b"xref\n0 13\n0000000000 65535 f \n"
    for idnum in range(1, 13):
        out += b"%010d 00000 n \n" % offsets[idnum]
    out += (b"trailer\n<< /Size 13 /Root 1 0 R /Encrypt 9 0 R /Info 10 0 R "
            b"/ID [<%s><%s>] >>\nstartxref\n%d\n%%%%EOF\n"
            % (ID1.hex().encode(), ID1.hex().encode(), xref))
    return bytes(out)


def _selection(reader: PdfReader) -> dict[str, str]:
    seen: dict[str, str] = {}
    original = Encryption._make_crypt_filter

    def wrapper(self, idnum, generation):
        cf = original(self, idnum, generation)
        seen.setdefault("stm", CLASS_OF[type(cf.stm_crypt)])
        seen.setdefault("str", CLASS_OF[type(cf.str_crypt)])
        seen.setdefault("ef", CLASS_OF[type(cf.ef_crypt)])
        return cf

    Encryption._make_crypt_filter = wrapper  # type: ignore[assignment]
    try:
        for idnum in (4, 7, 8, 10):
            IndirectObject(idnum, 0, reader).get_object()
    finally:
        Encryption._make_crypt_filter = original  # type: ignore[assignment]
    return seen


@pytest.mark.parametrize(
    ("method", "crypt_cls"),
    [("/V2", "CryptRC4"), ("/AESV2", "CryptAES"), ("/Identity", "CryptIdentity")],
)
def test_uniform_routing_selects_declared_filter(method, crypt_cls):
    pdf = _build_pdf(method, method, method, method, method, method)
    reader = PdfReader(BytesIO(pdf), password=PASSWORD)
    assert _selection(reader) == {"stm": crypt_cls, "str": crypt_cls, "ef": crypt_cls}
    # Every object round-trips when all three slots agree.
    assert zlib.decompress(IndirectObject(4, 0, reader).get_object()._data) == PAGE_TEXT
    assert IndirectObject(7, 0, reader).get_object()._data == ATTACH_PLAIN
    assert zlib.decompress(IndirectObject(8, 0, reader).get_object()._data) == ATTACH_FLATE
    assert reader.trailer["/Info"].get_object()["/Title"] == INFO_TITLE


def test_mixed_stmf_identity_and_strf_rc4():
    pdf = _build_pdf("/Identity", "/V2", "/V2", "/Identity", "/V2", "/V2")
    reader = PdfReader(BytesIO(pdf), password=PASSWORD)
    assert _selection(reader) == {"stm": "CryptIdentity", "str": "CryptRC4", "ef": "CryptRC4"}
    # Streams and strings are routed independently and both decode correctly.
    assert zlib.decompress(IndirectObject(4, 0, reader).get_object()._data) == PAGE_TEXT
    assert reader.trailer["/Info"].get_object()["/Title"] == INFO_TITLE


def test_eff_slot_is_ignored_for_embedded_files():
    """EFF differs from StmF: pypdf still decrypts the EF stream with StmF.

    Per PDF 1.7 §7.6.2 embedded-file streams must use EFF, but pypdf's
    CryptFilter.decrypt_object routes every StreamObject through stm_crypt and
    never calls ef_crypt, so a differing EFF produces garbled attachments.
    """
    pdf = _build_pdf("/V2", "/V2", "/AESV2", "/V2", "/V2", "/AESV2")
    reader = PdfReader(BytesIO(pdf), password=PASSWORD)
    selection = _selection(reader)
    assert selection["stm"] == "CryptRC4"
    assert selection["ef"] == "CryptAES"  # the EFF object is built ...

    # ... but its decrypt() is never used; object 7 was AES-protected yet pypdf
    # applies RC4 (StmF), so the bytes are wrong.
    assert IndirectObject(7, 0, reader).get_object()._data != ATTACH_PLAIN
    with pytest.raises(zlib.error):
        zlib.decompress(IndirectObject(8, 0, reader).get_object()._data)


def test_identity_eff_still_decrypted_with_stmf():
    """An Identity-protected EF stream is nonetheless run through StmF."""
    pdf = _build_pdf("/V2", "/V2", "/Identity", "/V2", "/V2", "/Identity")
    reader = PdfReader(BytesIO(pdf), password=PASSWORD)
    assert _selection(reader)["ef"] == "CryptIdentity"
    # Object 7 was stored as plaintext (Identity); RC4 mis-decrypts it.
    assert IndirectObject(7, 0, reader).get_object()._data != ATTACH_PLAIN


@pytest.mark.parametrize(
    ("stm", "strf", "eff", "message"),
    [
        ("/Bogus", "/V2", "/V2", "StmF Method /Bogus NOT supported!"),
        ("/V2", "/Bogus", "/V2", "StrF Method /Bogus NOT supported!"),
        ("/V2", "/V2", "/Bogus", "EFF Method /Bogus NOT supported!"),
        ("/V2", "/None", "/V2", "StrF Method /None NOT supported!"),
    ],
)
def test_unknown_cfm_fails_fast_before_password_check(stm, strf, eff, message):
    pdf = _build_pdf(stm, strf, eff, "/V2", "/V2", "/V2")
    with pytest.raises(NotImplementedError, match=re.escape(message)):
        PdfReader(BytesIO(pdf), password=PASSWORD)

