"""
Build local, fully controlled V4/R4 (128-bit) encrypted PDFs to audit which
Crypt Filter pypdf actually selects for streams, strings and embedded files.

Every generated document contains the same logical objects:
  * a flate-compressed page content stream        (routed via StmF)
  * text strings in /Info and the filespec/name tree (routed via StrF)
  * a plain (uncompressed) embedded file stream   (routed via EFF per spec)
  * a flate-compressed embedded file stream       (routed via EFF per spec)

The difference between documents is only the /CF + /StmF /StrF /EFF routing
in the encryption dictionary, so the bytes each object is encrypted with are
known and reproducible.
"""
from __future__ import annotations

import hashlib
import zlib
from pathlib import Path

from pypdf._encryption import Encryption
from pypdf._crypt_providers import CryptAES, CryptIdentity, CryptRC4

HERE = Path(__file__).resolve().parent
SAMPLE_DIR = HERE / "samples"

PASSWORD = "asdfzxcv"
P_PERMS = -4
ID1 = b"0123456789abcdef"  # stable 16-byte file id -> reproducible key

# Known plaintext payloads (ASCII so success/failure is unambiguous).
PAGE_TEXT = b"BT /F1 18 Tf 72 700 Td (Crypt filter audit page) Tj ET\n"
ATTACH_PLAIN = b"PLAIN-ATTACHMENT: this embedded file is never flate compressed.\n" * 4
ATTACH_FLATE = b"FLATE-ATTACHMENT: zlib wrapped, then encrypted payload.\n" * 8
INFO_TITLE = "Document title (StrF string)"
INFO_AUTHOR = "audit-author"
FILE_SPEC_NAME = "plain.txt"
FILE_SPEC_NAME2 = "flate.bin"
TREE_LABEL = "embed-label"


def derive_keys(file_key: bytes, idnum: int, gen: int = 0) -> tuple[bytes, bytes]:
    """Replicate Encryption._make_crypt_filter key derivation for V<=4."""
    pack1 = (idnum & 0xFFFFFF).to_bytes(3, "little")
    pack2 = (gen & 0xFFFF).to_bytes(2, "little")
    n = len(file_key)  # V != 1 -> Length/8
    base = hashlib.md5(file_key[:n] + pack1 + pack2)
    rc4_key = base.digest()[: min(n + 5, 16)]
    base.update(b"sAlT")
    aes_key = base.digest()[: min(n + 5, 16)]
    return rc4_key, aes_key


def make_crypt(method: str, rc4_key: bytes, aes_key: bytes):
    if method == "/AESV2":
        return CryptAES(aes_key)
    if method == "/Identity":
        return CryptIdentity()
    if method == "/V2":
        return CryptRC4(rc4_key)
    raise ValueError(f"generator does not implement {method}")


def enc_bytes(data: bytes, method: str, file_key: bytes, idnum: int) -> bytes:
    rc4_key, aes_key = derive_keys(file_key, idnum)
    return make_crypt(method, rc4_key, aes_key).encrypt(data)


def esc_text(s: str) -> bytes:
    # Latin-1 payloads; return the raw inner bytes. The caller always wraps
    # encrypted/clear string content as a PDF hex string <...>, which is the
    # only representation that safely carries arbitrary encrypted bytes.
    return s.encode("latin-1")


def as_pdf_string(data: bytes) -> bytes:
    return b"<" + data.hex().encode() + b">"


class Obj:
    def __init__(self, body: bytes, raw_stream: bytes | None = None,
                 stored_stream: bytes | None = None):
        self.body = body                  # dictionary bytes (inside << ... >>)
        self.raw_stream = raw_stream      # logical, pre-encryption stream bytes
        self.stored_stream = stored_stream  # exact bytes placed between stream/endstream


def build_objects(stm: str, strf: str, eff: str, file_key: bytes) -> dict[int, Obj]:
    """Construct the 8 encrypted indirect objects. Object 9 is the /Encrypt dict."""
    page_enc = zlib.compress(PAGE_TEXT)
    attach_flate_enc = zlib.compress(ATTACH_FLATE)

    objs: dict[int, Obj] = {}

    # 1 catalog
    objs[1] = Obj(b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 5 0 R >> >>")
    # 2 pages tree
    objs[2] = Obj(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    # 3 page
    objs[3] = Obj(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 12 0 R >> >> /Contents 4 0 R >>"
    )
    # 4 content stream: flate compressed, then StmF encrypted.
    objs[4] = Obj(
        b"<< /Length %d /Filter /FlateDecode >>" % len(enc_bytes(page_enc, stm, file_key, 4)),
        raw_stream=PAGE_TEXT,
        stored_stream=enc_bytes(page_enc, stm, file_key, 4),
    )
    # 5 name tree leaf: one distinct entry per embedded file.
    n1 = as_pdf_string(enc_bytes(esc_text(FILE_SPEC_NAME), strf, file_key, 5))
    n2 = as_pdf_string(enc_bytes(esc_text(FILE_SPEC_NAME2), strf, file_key, 5))
    objs[5] = Obj(
        b"<< /Names [%s 6 0 R %s 11 0 R] >>" % (n1, n2)
    )
    # 6 file specification (strings routed via StrF) -> plain embedded file 7
    fname = as_pdf_string(enc_bytes(esc_text(FILE_SPEC_NAME), strf, file_key, 6))
    ufname = as_pdf_string(enc_bytes(esc_text(FILE_SPEC_NAME), strf, file_key, 6))
    desc = as_pdf_string(enc_bytes(esc_text("plain (uncompressed) embedded file"), strf, file_key, 6))
    objs[6] = Obj(
        b"<< /Type /Filespec /F %s /UF %s /Desc %s "
        b"/EF << /F 7 0 R /UF 7 0 R >> >>" % (fname, ufname, desc)
    )
    # 11 file specification -> flate compressed embedded file 8
    f2 = as_pdf_string(enc_bytes(esc_text(FILE_SPEC_NAME2), strf, file_key, 11))
    desc2 = as_pdf_string(enc_bytes(esc_text("flate compressed embedded file"), strf, file_key, 11))
    objs[11] = Obj(
        b"<< /Type /Filespec /F %s /UF %s /Desc %s "
        b"/EF << /F 8 0 R /UF 8 0 R >> >>" % (f2, f2, desc2)
    )
    # 7 plain embedded file: EFF encrypted, no compression.
    # NOTE: a PDF name containing a literal '/' must encode it as '#2F';
    # use the slash-free short subtype to keep the dictionary unambiguous.
    objs[7] = Obj(
        b"<< /Type /EmbeddedFile /Subtype /octet-stream /Length %d >>"
        % len(enc_bytes(ATTACH_PLAIN, eff, file_key, 7)),
        raw_stream=ATTACH_PLAIN,
        stored_stream=enc_bytes(ATTACH_PLAIN, eff, file_key, 7),
    )
    # 8 flate embedded file: compressed then EFF encrypted.
    objs[8] = Obj(
        b"<< /Type /EmbeddedFile /Filter /FlateDecode /Length %d >>"
        % len(enc_bytes(attach_flate_enc, eff, file_key, 8)),
        raw_stream=ATTACH_FLATE,
        stored_stream=enc_bytes(attach_flate_enc, eff, file_key, 8),
    )
    # 10 info dictionary
    title = as_pdf_string(enc_bytes(esc_text(INFO_TITLE), strf, file_key, 10))
    author = as_pdf_string(enc_bytes(esc_text(INFO_AUTHOR), strf, file_key, 10))
    objs[10] = Obj(b"<< /Title %s /Author %s >>" % (title, author))
    # 12 simple font referenced by the page (unencrypted content dict)
    objs[12] = Obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    return objs


def build_encrypt_dict(stm: str, strf: str, eff: str, encryption: Encryption) -> bytes:
    cfms = {"/V2": "/V2", "/AESV2": "/AESV2", "/Identity": "/Identity",
            "/None": "/None", "/Bogus": "/Bogus"}
    names = {"RC4": "/RC4CF", "AES": "/AESCF", "ID": "/IdCF",
             "NONE": "/NoneCF", "BOGUS": "/BogusCF"}
    cf_entries = []
    used = set()
    for m in (stm, strf, eff):
        if m == "/Identity":
            continue
        used.add(m)
    label = {"/V2": "RC4", "/AESV2": "AES", "/None": "NONE", "/Bogus": "BOGUS"}
    for m in used:
        cf_entries.append(
            b"%s << /AuthEvent /DocOpen /CFM %s /Length 16 >>"
            % (names[label[m]].encode(), cfms[m].encode())
        )
    route = {"/V2": "/RC4CF", "/AESV2": "/AESCF", "/Identity": "/Identity",
             "/None": "/NoneCF", "/Bogus": "/BogusCF"}
    parts = [
        b"<< /Filter /Standard /V 4 /R 4 /Length 128 /P %d" % P_PERMS,
        b"/O <%s>" % encryption.values.O.hex().encode(),
        b"/U <%s>" % encryption.values.U.hex().encode(),
        b"/CF << %s >>" % b" ".join(cf_entries),
        b"/StmF %s /StrF %s /EFF %s" % (
            route[stm].encode(), route[strf].encode(), route[eff].encode()),
        b">>",
    ]
    return b" ".join(parts)


def serialize(objs: dict[int, Obj], encrypt_dict: bytes) -> bytes:
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    ordered = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    for idnum in ordered:
        offsets[idnum] = len(out)
        if idnum == 9:
            out += b"9 0 obj\n" + encrypt_dict + b"\nendobj\n"
            continue
        obj = objs[idnum]
        out += f"{idnum} 0 obj\n".encode() + obj.body + b"\n"
        if obj.stored_stream is not None:
            # PDF 1.7 §7.3.8.1: the keyword stream is followed by an EOL and
            # the stream data is followed by an EOL before endstream. /Length
            # counts only the data bytes, so the trailing EOL is excluded.
            out += b"stream\n" + obj.stored_stream + b"\nendstream\n"
        out += b"endobj\n"
    xref_pos = len(out)
    max_id = 12
    out += b"xref\n0 %d\n" % (max_id + 1)
    out += b"0000000000 65535 f \n"
    for idnum in range(1, max_id + 1):
        out += b"%010d 00000 n \n" % offsets[idnum]
    out += (
        b"trailer\n<< /Size %d /Root 1 0 R /Encrypt 9 0 R /Info 10 0 R "
        b"/ID [<%s><%s>] >>\nstartxref\n%d\n%%%%EOF\n"
        % (max_id + 1, ID1.hex().encode(), ID1.hex().encode(), xref_pos)
    )
    return bytes(out)


def make_encryption() -> Encryption:
    enc = Encryption(
        V=4, R=4, Length=128, P=P_PERMS, EncryptMetadata=True,
        first_id_entry=ID1, StmF="/V2", StrF="/V2", EFF="/V2",
        values=None, entry=None,  # type: ignore[arg-type]
    )
    enc.compute_values_v4(PASSWORD.encode("latin-1"), PASSWORD.encode("latin-1"))
    return enc


# Each entry:
#   filename, StmF(label), StrF(label), EFF(label), encrypt-method triple.
# The label is what the /CF dictionary advertises; the method triple is the
# real algorithm used to encrypt object bytes (the generator must be able to
# produce them). Malformed samples advertise an unsupported label while their
# bytes are still protected by a real algorithm so authentication succeeds
# and the failure occurs specifically at crypt-filter selection.
CONFIGS = [
    ("all-rc4",              "/V2",       "/V2",       "/V2",
     ("/V2", "/V2", "/V2")),
    ("all-aes",              "/AESV2",    "/AESV2",    "/AESV2",
     ("/AESV2", "/AESV2", "/AESV2")),
    ("all-identity",         "/Identity", "/Identity", "/Identity",
     ("/Identity", "/Identity", "/Identity")),
    ("stm-identity-str-rc4", "/Identity", "/V2",       "/V2",
     ("/Identity", "/V2", "/V2")),
    ("stm-aes-str-rc4",      "/AESV2",    "/V2",       "/V2",
     ("/AESV2", "/V2", "/V2")),
    ("eff-aes-mismatch",     "/V2",       "/V2",       "/AESV2",
     ("/V2", "/V2", "/AESV2")),
    ("eff-identity-mismatch","/V2",       "/V2",       "/Identity",
     ("/V2", "/V2", "/Identity")),
    # --- malformed / unsupported declarations (bytes are real RC4) ---
    ("unknown-stmf",         "/Bogus",    "/V2",       "/V2",
     ("/V2", "/V2", "/V2")),
    ("unknown-eff",          "/V2",       "/V2",       "/Bogus",
     ("/V2", "/V2", "/V2")),
    ("none-strf",            "/V2",       "/None",     "/V2",
     ("/V2", "/V2", "/V2")),
]


def build_stream_crypt_specifier(enc: Encryption, file_key: bytes) -> bytes:
    """A valid RC4 doc whose page stream uses a per-stream /Crypt specifier.

    PDF 1.7 7.4.10: a /Crypt entry in the stream's /Filter array with a
    /Name referencing a crypt filter is a legal construction that pypdf does
    not implement.
    """
    objs = build_objects("/V2", "/V2", "/V2", file_key)
    page_enc = zlib.compress(PAGE_TEXT)
    stored = enc_bytes(page_enc, "/V2", file_key, 4)
    objs[4].body = (
        b"<< /Length %d /Filter [/FlateDecode /Crypt] "
        b"/DecodeParms [null << /Name /RC4CF >>] >>" % len(stored)
    )
    objs[4].stored_stream = stored
    return serialize(objs, build_encrypt_dict("/V2", "/V2", "/V2", enc))


def main() -> None:
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    enc = make_encryption()
    file_key = enc._key
    assert file_key is not None
    for name, stm, strf, eff, methods in CONFIGS:
        m_stm, m_str, m_eff = methods
        objs = build_objects(m_stm, m_str, m_eff, file_key)
        encrypt_dict = build_encrypt_dict(stm, strf, eff, enc)
        pdf = serialize(objs, encrypt_dict)
        path = SAMPLE_DIR / f"{name}.pdf"
        path.write_bytes(pdf)
        print(f"wrote {path.name:28s} StmF={stm:9s} StrF={strf:9s} EFF={eff:9s} ({len(pdf)} bytes)")
    crypt_pdf = build_stream_crypt_specifier(enc, file_key)
    crypt_path = SAMPLE_DIR / "stream-crypt-specifier.pdf"
    crypt_path.write_bytes(crypt_pdf)
    print(f"wrote {crypt_path.name:28s} per-stream /Crypt filter (unsupported)")
    print(f"\nfile encryption key (hex): {file_key.hex()}")
    print(f"password: {PASSWORD!r}")


if __name__ == "__main__":
    main()
