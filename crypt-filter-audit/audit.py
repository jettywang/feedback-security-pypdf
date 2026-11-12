"""
Audit which Crypt Filter pypdf actually selects for streams, strings and
embedded-file streams after successful authentication.

For every generated sample this harness:
  1. wraps Encryption._make_crypt_filter to record the concrete CryptBase
     subclass pypdf instantiates for the StmF, StrF and EFF slots;
  2. authenticates with the user password and reads back each audited object,
     recording the exact post-authentication bytes pypdf exposes;
  3. compares those bytes against the known plaintext/compressed plaintext and
     classifies the outcome (correct / misdecrypted / raised error).

Results are written as JSON to results/audit.json and a human report to
results/audit.txt.
"""
from __future__ import annotations

import json
import logging
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

import generate_samples as gen
from pypdf import PdfReader
from pypdf._encryption import Encryption
from pypdf._crypt_providers import CryptAES, CryptIdentity, CryptRC4

HERE = Path(__file__).resolve().parent
SAMPLE_DIR = HERE / "samples"
RESULT_DIR = HERE / "results"

CLASS_NAME = {CryptRC4: "CryptRC4(/V2)", CryptAES: "CryptAES",
              CryptIdentity: "CryptIdentity(/Identity)"}


@dataclass
class SlotSelection:
    stm: str = ""
    str_: str = ""
    ef: str = ""


@dataclass
class ObjectResult:
    object: str
    idnum: int
    routed_by_spec: str          # StmF / StrF / EFF
    declared_method: str         # label advertised in /CF
    expected: str                # what correct decryption should yield
    status: str                  # correct | misdecrypted | error
    detail: str = ""
    observed_hex_prefix: str = ""
    observed_len: int = 0


@dataclass
class SampleResult:
    sample: str
    declared: dict
    selection: dict = field(default_factory=dict)
    authenticated: bool = False
    raised: dict | None = None
    objects: list = field(default_factory=list)


def install_probe() -> tuple[SlotSelection, object]:
    slot = SlotSelection()
    original = Encryption._make_crypt_filter

    def wrapper(self, idnum, generation):
        cf = original(self, idnum, generation)
        # Retain the first concrete selection; later decryptions reuse cached
        # objects and may not rebuild a filter, so never blank the slots out.
        slot.stm = slot.stm or CLASS_NAME.get(type(cf.stm_crypt), type(cf.stm_crypt).__name__)
        slot.str_ = slot.str_ or CLASS_NAME.get(type(cf.str_crypt), type(cf.str_crypt).__name__)
        slot.ef = slot.ef or CLASS_NAME.get(type(cf.ef_crypt), type(cf.ef_crypt).__name__)
        return cf

    Encryption._make_crypt_filter = wrapper  # type: ignore[assignment]
    return slot, original


def restore(original) -> None:
    Encryption._make_crypt_filter = original  # type: ignore[assignment]


def hx(data: bytes, n: int = 24) -> str:
    return data[:n].hex()


def assess_bytes(observed: bytes, expected_plain: bytes, *, flate: bool) -> tuple[str, str]:
    if flate:
        try:
            decompressed = zlib.decompress(observed)
        except zlib.error as exc:
            return "misdecrypted", f"zlib error after decrypt: {exc}"
        if decompressed == expected_plain:
            return "correct", "decompressed bytes match plaintext"
        return "misdecrypted", "decompressed bytes differ"
    if observed == expected_plain:
        return "correct", "raw bytes match plaintext"
    return "misdecrypted", "raw bytes differ (wrong crypt filter/key)"


def audit_sample(name: str, stm: str, strf: str, eff: str, methods) -> SampleResult:
    result = SampleResult(
        sample=name,
        declared={"StmF": stm, "StrF": strf, "EFF": eff,
                  "encrypt_methods": {"StmF": methods[0], "StrF": methods[1], "EFF": methods[2]}},
    )
    slot, original = install_probe()
    try:
        reader = PdfReader(str(SAMPLE_DIR / f"{name}.pdf"), password=gen.PASSWORD)
        result.authenticated = reader.is_encrypted

        # Object 4: page content stream (flate), routed via StmF.
        from pypdf.generic import IndirectObject
        content = IndirectObject(4, 0, reader).get_object()
        raw = content._data
        status, detail = assess_bytes(raw, gen.PAGE_TEXT, flate=True)
        result.objects.append(ObjectResult(
            "page content stream", 4,
            "StmF", stm, "zlib(PAGE_TEXT)", status, detail,
            hx(raw), len(raw)))

        # Object 10: /Info strings, routed via StrF.
        info = reader.trailer["/Info"].get_object()
        title = info.get("/Title")
        title_bytes = title.get_encoded_bytes() if title is not None else b""
        ok = title == gen.INFO_TITLE
        result.objects.append(ObjectResult(
            "Info /Title string", 10, "StrF", strf, gen.INFO_TITLE,
            "correct" if ok else "misdecrypted",
            "text round-trips" if ok else f"got {title!r}",
            hx(title_bytes), len(title_bytes)))

        # Embedded files 7 (plain) and 8 (flate), routed via EFF per spec.
        filespecs = {
            7: ("plain embedded file (no compression)", gen.ATTACH_PLAIN, False),
            8: ("flate embedded file", gen.ATTACH_FLATE, True),
        }
        for idnum, (label, plain, is_flate) in filespecs.items():
            stream = IndirectObject(idnum, 0, reader).get_object()
            observed = stream._data
            status, detail = assess_bytes(observed, plain, flate=is_flate)
            # Also record what the public attachments API hands back.
            result.objects.append(ObjectResult(
                label, idnum, "EFF", eff,
                "zlib(plaintext)" if is_flate else "plaintext",
                status, detail, hx(observed), len(observed)))

        # Snapshot only after at least one object was decrypted, because the
        # filter is built lazily on first object access rather than at open().
        result.selection = {"stm_crypt": slot.stm, "str_crypt": slot.str_,
                            "ef_crypt": slot.ef}
    except Exception as exc:  # noqa: BLE001 - record every failure mode
        result.raised = {"type": type(exc).__name__, "message": str(exc)}
        result.selection = {"stm_crypt": slot.stm, "str_crypt": slot.str_,
                            "ef_crypt": slot.ef}
    finally:
        restore(original)
    return result


def main() -> None:
    logging.disable(logging.CRITICAL)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for name, stm, strf, eff, methods in gen.CONFIGS:
        results.append(asdict(audit_sample(name, stm, strf, eff, methods)))

    json_path = RESULT_DIR / "audit.json"
    json_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    lines = []
    for r in results:
        d = r["declared"]
        lines.append("=" * 88)
        lines.append(f"sample={r['sample']}.pdf  "
                     f"declared StmF={d['StmF']} StrF={d['StrF']} EFF={d['EFF']}")
        if r["raised"]:
            lines.append(f"  RAISED {r['raised']['type']}: {r['raised']['message']}")
            lines.append(f"  selection at failure -> stm={r['selection'].get('stm_crypt')} "
                         f"str={r['selection'].get('str_crypt')} ef={r['selection'].get('ef_crypt')}")
            continue
        sel = r["selection"]
        lines.append(f"  pypdf instantiated -> stm_crypt={sel['stm_crypt']}  "
                     f"str_crypt={sel['str_crypt']}  ef_crypt={sel['ef_crypt']}")
        for o in r["objects"]:
            lines.append(
                f"   [{o['status']:13s}] {o['object']:32s} obj={o['idnum']:<3d} "
                f"spec={o['routed_by_spec']} declared={o['declared_method']:9s} "
                f"len={o['observed_len']:<4d} {o['detail']}")
    text = "\n".join(lines)
    (RESULT_DIR / "audit.txt").write_text(text)
    print(text)
    print(f"\nJSON written to {json_path}")


if __name__ == "__main__":
    main()
