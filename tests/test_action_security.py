"""Tests for the optional action inspection and cleanup helpers.

The markers used below are plain strings. Nothing in these tests executes a
script, launches a program or opens a file; the action dictionaries are only
parsed, reported and removed.
"""
from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.actions import (
    ActionFinding,
    ActionPolicy,
    ActionScanner,
    LocationKind,
    sanitize_actions,
)
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    TextStringObject,
)

# Markers are inert strings; they are never interpreted by a PDF processor.
JS_MARKER = "MARKER_JAVASCRIPT_DO_NOT_RUN"
LAUNCH_MARKER = "MARKER_LAUNCH_DO_NOT_RUN"
REMOTE_FILE_MARKER = "MARKER_REMOTE_FILE_DO_NOT_OPEN"
EMBEDDED_FILE_MARKER = "MARKER_EMBEDDED_FILE_DO_NOT_OPEN"
WEB_LINK = "https://example.test/allowed"
NAV_DEST_MARKER = "MARKER_INTERNAL_DESTINATION"


@pytest.fixture
def writer_with_page():
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    return writer


def make_action(writer: PdfWriter, action_type: str, **entries: object) -> IndirectObject:
    """Create an indirect action dictionary holding inert marker strings only."""
    action = DictionaryObject()
    action[NameObject("/S")] = NameObject(action_type)
    for key, value in entries.items():
        action[NameObject(key)] = value
    return writer._add_object(action)


def make_link(writer: PdfWriter, action: DictionaryObject | IndirectObject) -> IndirectObject:
    annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject(),
            NameObject("/A"): action,
        }
    )
    return writer._add_object(annotation)


def finding_by_type(findings: list[ActionFinding], action_type: str) -> ActionFinding:
    matches = [finding for finding in findings if finding.action_type == action_type]
    assert len(matches) == 1
    return matches[0]


def test_empty_document_has_no_findings(writer_with_page):
    scanner = ActionScanner(writer_with_page)
    assert scanner.scan() == []
    assert scanner.denied_findings() == []
    assert scanner.allowed_findings() == []


def test_scan_finds_catalog_open_action_and_reports_source(writer_with_page):
    writer = writer_with_page
    javascript = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject(JS_MARKER)}
    )
    writer.root_object[NameObject("/OpenAction")] = javascript

    findings = writer.scan_actions().findings
    finding = finding_by_type(findings, "/JavaScript")
    assert finding.allowed is False
    assert "JavaScript" in finding.reason
    assert finding.locations[0].kind is LocationKind.CATALOG_OPEN_ACTION
    assert finding.locations[0].path == "catalog /OpenAction"
    assert finding.indirect_reference is not None


def test_catalog_destination_array_is_plain_navigation(writer_with_page):
    writer = writer_with_page
    writer.root_object[NameObject("/OpenAction")] = ArrayObject(
        [writer.pages[0].indirect_reference, NameObject("/Fit")]
    )
    # A destination array has no action dictionary and must not be reported.
    assert writer.scan_actions().findings == []
    writer.sanitize_actions()
    assert isinstance(
        writer.root_object["/OpenAction"], ArrayObject
    )


def test_scan_finds_page_and_annotation_events(writer_with_page):
    writer = writer_with_page
    page = writer.pages[0]
    launch = make_action(
        writer, "/Launch", **{"/F": TextStringObject(LAUNCH_MARKER)}
    )
    page[NameObject("/AA")] = DictionaryObject({NameObject("/O"): launch})

    javascript = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject(JS_MARKER)}
    )
    annotation_aa = DictionaryObject({NameObject("/E"): javascript})
    annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject(),
            NameObject("/AA"): writer._add_object(annotation_aa),
        }
    )
    page[NameObject("/Annots")] = writer._add_object(
        ArrayObject([writer._add_object(annotation)])
    )

    findings = writer.scan_actions().findings
    launch_finding = finding_by_type(findings, "/Launch")
    assert launch_finding.locations[0].kind is LocationKind.PAGE_AA
    assert launch_finding.locations[0].trigger == "/O"
    assert launch_finding.locations[0].page_index == 0

    javascript_finding = finding_by_type(findings, "/JavaScript")
    assert javascript_finding.locations[0].kind is LocationKind.ANNOTATION_AA
    assert "/Annots[0] /AA /E" in javascript_finding.source_paths[0]


def test_scan_finds_form_field_actions_through_kids(writer_with_page):
    writer = writer_with_page
    javascript = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject(JS_MARKER)}
    )
    kid_field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("child"),
            NameObject("/AA"): DictionaryObject({NameObject("/K"): javascript}),
        }
    )
    parent_field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("parent"),
            NameObject("/Kids"): writer._add_object(
                ArrayObject([writer._add_object(kid_field)])
            ),
        }
    )
    form = DictionaryObject(
        {NameObject("/Fields"): writer._add_object(
            ArrayObject([writer._add_object(parent_field)])
        )}
    )
    writer.root_object[NameObject("/AcroForm")] = writer._add_object(form)

    finding = finding_by_type(writer.scan_actions().findings, "/JavaScript")
    assert finding.locations[0].kind is LocationKind.FIELD_AA
    assert "/Kids[0] /AA /K" in finding.locations[0].path


def test_scan_finds_document_javascript_name_tree(writer_with_page):
    writer = writer_with_page
    javascript = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject(JS_MARKER)}
    )
    pairs = writer._add_object(
        ArrayObject([TextStringObject("marker-name"), javascript])
    )
    tree = writer._add_object(DictionaryObject({NameObject("/Names"): pairs}))
    writer.root_object[NameObject("/Names")] = DictionaryObject(
        {NameObject("/JavaScript"): tree}
    )

    finding = finding_by_type(writer.scan_actions().findings, "/JavaScript")
    assert finding.locations[0].kind is LocationKind.JAVASCRIPT_NAME_TREE
    assert finding.locations[0].container is pairs.get_object()


def test_next_chain_dictionary_and_array_are_walked(writer_with_page):
    writer = writer_with_page
    goto = make_action(
        writer, "/GoTo", **{"/D": TextStringObject(NAV_DEST_MARKER)}
    )
    remote = make_action(
        writer,
        "/GoToR",
        **{
            "/F": TextStringObject(REMOTE_FILE_MARKER),
            "/D": TextStringObject("remote-dest"),
        },
    )
    embedded = make_action(
        writer,
        "/GoToE",
        **{"/F": TextStringObject(EMBEDDED_FILE_MARKER)},
    )
    uri = make_action(writer, "/URI", **{"/URI": TextStringObject(WEB_LINK)})
    uri.get_object()[NameObject("/Next")] = writer._add_object(
        ArrayObject([goto, remote])
    )
    # A second, dictionary-shaped /Next level.
    remote.get_object()[NameObject("/Next")] = embedded

    writer.pages[0][NameObject("/Annots")] = writer._add_object(
        ArrayObject([make_link(writer, uri)])
    )

    findings = writer.scan_actions().findings
    by_type = {finding.action_type: finding for finding in findings}
    assert set(by_type) == {"/URI", "/GoTo", "/GoToR", "/GoToE"}
    assert by_type["/URI"].allowed is True
    assert by_type["/GoTo"].allowed is True
    assert by_type["/GoToR"].allowed is False
    assert by_type["/GoToE"].allowed is False
    assert all(
        location.kind is LocationKind.NEXT_ACTION
        for location in by_type["/GoToR"].locations
    )
    assert "/Next" in by_type["/GoToR"].locations[0].path


def test_cyclic_next_chain_terminates(writer_with_page, caplog):
    writer = writer_with_page
    first = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject("MARKER_CYCLE_A")}
    )
    second = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject("MARKER_CYCLE_B")}
    )
    first.get_object()[NameObject("/Next")] = second
    second.get_object()[NameObject("/Next")] = first

    writer.pages[0][NameObject("/Annots")] = writer._add_object(
        ArrayObject([make_link(writer, first)])
    )

    with caplog.at_level("WARNING"):
        findings = writer.scan_actions().findings

    # The loop terminates and the two distinct actions are reported once each.
    assert len(findings) == 2
    assert "cycle" in caplog.text.lower()


def test_shared_indirect_action_reports_every_location(writer_with_page):
    writer = writer_with_page
    launch = make_action(
        writer, "/Launch", **{"/F": TextStringObject(LAUNCH_MARKER)}
    )
    writer.pages[0][NameObject("/Annots")] = writer._add_object(
        ArrayObject([make_link(writer, launch), make_link(writer, launch)])
    )

    finding = finding_by_type(writer.scan_actions().findings, "/Launch")
    paths = finding.source_paths
    assert len(paths) == 2
    assert "/Annots[0] /A" in paths[0]
    assert "/Annots[1] /A" in paths[1]


def test_default_policy_allows_only_navigation_and_web_links():
    policy = ActionPolicy()
    cases = {
        "/GoTo": True,
        "/SetOCGState": True,
        "/URI": True,
        "/JavaScript": False,
        "/Launch": False,
        "/GoToR": False,
        "/GoToE": False,
        "/Rendition": False,
        "/RichMediaExecute": False,
        "/SubmitForm": False,
    }
    for action_type, expected in cases.items():
        entries = {NameObject("/S"): NameObject(action_type)}
        if action_type == "/URI":
            entries[NameObject("/URI")] = TextStringObject(WEB_LINK)
        action = DictionaryObject(entries)
        allowed, _ = policy.evaluate(action)
        assert allowed is expected, action_type

    missing_s = DictionaryObject()
    allowed, reason = policy.evaluate(missing_s)
    assert allowed is False
    assert "/S" in reason


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("https://example.test/page", True),
        ("http://example.test/page", True),
        ("javascript:alert(1)", False),
        ("file:///etc/passwd", False),
        ("ftp://files.test/data", False),
        ("mailto:user@example.test", False),
        ("/relative/path", False),
    ],
)
def test_uri_scheme_policy(uri, expected):
    policy = ActionPolicy()
    action = DictionaryObject(
        {
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject(uri),
        }
    )
    allowed, reason = policy.evaluate(action)
    assert allowed is expected
    assert reason


def test_uri_host_allowlist():
    policy = ActionPolicy(allowed_uri_hosts={"allowed.test"})
    accepted = DictionaryObject(
        {
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://allowed.test/x"),
        }
    )
    rejected = DictionaryObject(
        {
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://evil.test/x"),
        }
    )
    assert policy.evaluate(accepted)[0] is True
    allowed, reason = policy.evaluate(rejected)
    assert allowed is False
    assert "evil.test" in reason


def test_custom_action_type_allowlist():
    policy = ActionPolicy(allowed_action_types={"/Named"})
    named = DictionaryObject(
        {
            NameObject("/S"): NameObject("/Named"),
            NameObject("/N"): NameObject("/Print"),
        }
    )
    assert policy.evaluate(named)[0] is True
    # Dangerous types cannot be enabled accidentally through a custom policy.
    assert ActionPolicy(allowed_action_types={"/JavaScript"}).evaluate(
        DictionaryObject({NameObject("/S"): NameObject("/JavaScript")})
    )[0] is True


def test_sanitize_removes_denied_actions_and_keeps_navigation(writer_with_page):
    writer = writer_with_page
    page = writer.pages[0]
    javascript = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject(JS_MARKER)}
    )
    writer.root_object[NameObject("/OpenAction")] = javascript
    page[NameObject("/AA")] = DictionaryObject(
        {
            NameObject("/O"): make_action(
                writer, "/Launch", **{"/F": TextStringObject(LAUNCH_MARKER)}
            )
        }
    )

    goto = make_action(
        writer, "/GoTo", **{"/D": TextStringObject(NAV_DEST_MARKER)}
    )
    remote = make_action(
        writer,
        "/GoToR",
        **{"/F": TextStringObject(REMOTE_FILE_MARKER)},
    )
    uri = make_action(writer, "/URI", **{"/URI": TextStringObject(WEB_LINK)})
    uri.get_object()[NameObject("/Next")] = writer._add_object(
        ArrayObject([goto, remote])
    )
    link = make_link(writer, uri)
    plain_destination = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject(),
            NameObject("/Dest"): TextStringObject(NAV_DEST_MARKER),
        }
    )
    page[NameObject("/Annots")] = writer._add_object(
        ArrayObject([link, writer._add_object(plain_destination)])
    )

    cleanup = sanitize_actions(writer)
    removed = {finding.action_type for finding in cleanup if not finding.allowed}
    assert removed == {"/JavaScript", "/Launch", "/GoToR"}

    # Re-open the reachable action graph and verify only allowed actions stay.
    verification = writer.scan_actions()
    assert verification.denied_findings() == []
    kept = {finding.action_type for finding in verification.allowed_findings()}
    assert kept == {"/URI", "/GoTo"}

    assert "/OpenAction" not in writer.root_object
    assert "/AA" not in page
    remaining_chain = uri.get_object()["/Next"].get_object()
    assert [item.get_object()["/S"] for item in remaining_chain] == ["/GoTo"]
    annotations = page["/Annots"].get_object()
    assert "/Dest" in annotations[1].get_object()


def test_sanitize_prunes_name_tree_pairs(writer_with_page):
    writer = writer_with_page
    first = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject("MARKER_NT_1")}
    )
    second = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject("MARKER_NT_2")}
    )
    pairs = writer._add_object(
        ArrayObject(
            [TextStringObject("name-1"), first, TextStringObject("name-2"), second]
        )
    )
    tree = writer._add_object(DictionaryObject({NameObject("/Names"): pairs}))
    writer.root_object[NameObject("/Names")] = DictionaryObject(
        {NameObject("/JavaScript"): tree}
    )

    sanitize_actions(writer)
    assert list(pairs) == []
    assert "/Names" not in writer.root_object
    assert writer.scan_actions().findings == []


def test_sanitize_round_trip_through_file(writer_with_page):
    writer = writer_with_page
    page = writer.pages[0]
    uri = make_action(writer, "/URI", **{"/URI": TextStringObject(WEB_LINK)})
    page[NameObject("/Annots")] = writer._add_object(
        ArrayObject([make_link(writer, uri)])
    )
    writer.root_object[NameObject("/OpenAction")] = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject(JS_MARKER)}
    )

    sanitize_actions(writer)
    buffer = BytesIO()
    writer.write(buffer)
    buffer.seek(0)

    reader = PdfReader(buffer)
    reopened = PdfWriter()
    reopened.clone_reader_document_root(reader)
    assert reopened.scan_actions().denied_findings() == []
    kept = reopened.scan_actions().allowed_findings()
    assert len(kept) == 1
    assert kept[0].action_type == "/URI"


def test_writer_sanitize_actions_returns_verification_scan(writer_with_page):
    writer = writer_with_page
    writer.root_object[NameObject("/OpenAction")] = make_action(
        writer, "/JavaScript", **{"/JS": TextStringObject(JS_MARKER)}
    )
    verification = writer.sanitize_actions()
    assert isinstance(verification, ActionScanner)
    assert verification.denied_findings() == []


def test_malformed_entries_are_skipped_without_failing(writer_with_page, caplog):
    writer = writer_with_page
    page = writer.pages[0]
    page[NameObject("/AA")] = DictionaryObject(
        {NameObject("/O"): TextStringObject("not-an-action")}
    )
    page[NameObject("/Annots")] = writer._add_object(
        ArrayObject([TextStringObject("not-an-annotation")])
    )

    with caplog.at_level("WARNING"):
        findings = writer.scan_actions().findings
    assert findings == []
    assert "malformed" in caplog.text.lower()
