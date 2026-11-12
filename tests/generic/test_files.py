"""Test the pypdf.generic._files module."""
import datetime
import hashlib
import shutil
import subprocess
from io import BytesIO
from pathlib import Path

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.constants import AFRelationship
from pypdf.errors import PdfReadError, PyPdfError
from pypdf.generic import (
    ArrayObject,
    AttachmentSource,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
    EmbeddedFile,
    IndirectObject,
    NameObject,
    NullObject,
    NumberObject,
    TextStringObject,
    create_string_object,
)
from tests import RESOURCE_ROOT, SAMPLE_ROOT, get_data_from_url

PDFATTACH_BINARY = shutil.which("pdfattach")


@pytest.mark.skipif(PDFATTACH_BINARY is None, reason="Requires poppler-utils")
def test_embedded_file__basic(tmp_path: Path) -> None:
    assert PDFATTACH_BINARY is not None
    clean_path = SAMPLE_ROOT / "002-trivial-libre-office-writer" / "002-trivial-libre-office-writer.pdf"
    attached_path = tmp_path / "attached.pdf"
    file_path = tmp_path / "test.txt"
    file_path.write_bytes(b"Hello World\n")
    subprocess.run([PDFATTACH_BINARY, clean_path, file_path, attached_path])  # noqa: S603
    with PdfReader(str(attached_path)) as reader:
        attachment = next(iter(EmbeddedFile._load(reader.root_object)))

        assert attachment.name == "test.txt"
        assert attachment.alternative_name == "test.txt"
        assert attachment.description is None
        assert attachment.associated_file_relationship == AFRelationship.UNSPECIFIED
        assert attachment.subtype is None
        assert attachment.content == b"Hello World\n"
        assert attachment.size == 12
        assert attachment.creation_date is None
        assert attachment.modification_date is None
        assert attachment.checksum is None
        assert repr(attachment) == "<EmbeddedFile name='test.txt'>"


def test_embedded_file__artificial() -> None:
    # No alternative name.
    pdf_object = DictionaryObject(answer=42)
    attachment = EmbeddedFile(name="dummy", pdf_object=pdf_object)
    assert attachment.alternative_name is None

    # No /EF.
    with pytest.raises(PdfReadError, match=f"/EF entry not found: {pdf_object}"):
        _ = attachment._embedded_file

    # Empty /EF dictionary.
    pdf_object = DictionaryObject()
    pdf_object[NameObject("/EF")] = DictionaryObject()
    attachment = EmbeddedFile(name="dummy", pdf_object=pdf_object)
    with pytest.raises(PdfReadError, match=r"No /\(U\)F key found in file dictionary: {}"):
        _ = attachment._embedded_file

    # Missing /Params key.
    pdf_object[NameObject("/EF")] = DictionaryObject(
        {
            NameObject("/F"): DictionaryObject(answer=42)
        }
    )

    # An actual checksum is set.
    # Generated using `hashlib.md5(b"Hello World!\n").digest()`
    params = DictionaryObject()
    params[NameObject("/CheckSum")] = ByteStringObject(b"\x8d\xdd\x8b\xe4\xb1y\xa5)\xaf\xa5\xf2\xff\xaeK\x98X")
    pdf_object[NameObject("/EF")] = DictionaryObject(
        {
            NameObject("/F"): DictionaryObject(
                {
                    NameObject("/Params"): params
                }
            )
        }
    )
    assert attachment.checksum == b"\x8d\xdd\x8b\xe4\xb1y\xa5)\xaf\xa5\xf2\xff\xaeK\x98X"


@pytest.mark.enable_socket
def test_embedded_file__kids() -> None:
    # Generated using the instructions available from
    # https://medium.com/@pymupdf/zugferd-and-ghostscript-how-to-create-industry-standard-and-compliant-pdf-e-invoices-83c9fde31ee5
    # Notes:
    #   * Yes, we need the full paths. Otherwise, the output file will only have an empty page.
    #   * The XML file has been a custom basic text file.
    #   * The input PDF file has been the `002-trivial-libre-office-writer.pdf` file.
    url = "https://github.com/user-attachments/files/18691309/embedded_files_kids.pdf"
    name = "embedded_files_kids.pdf"
    reader = PdfReader(BytesIO(get_data_from_url(url=url, name=name)))
    attachments = list(EmbeddedFile._load(reader.root_object))
    assert len(attachments) == 1
    attachment = attachments[0]

    assert attachment.name == "factur-x.xml"
    assert attachment.alternative_name == "factur-x.xml"
    assert attachment.description == "ZUGFeRD electronic invoice"
    assert attachment.associated_file_relationship == AFRelationship.ALTERNATIVE
    assert attachment.subtype == "/text/xml"
    assert attachment.content.startswith(b"Hello World!\n\nLorem ipsum dolor sit amet, ")
    assert attachment.content.endswith(b"\ntakimata sanctus est Lorem ipsum dolor sit amet.\n")
    assert attachment.size == 606
    assert attachment.creation_date is None
    assert attachment.modification_date == datetime.datetime(
        2013, 1, 21, 8, 14, 33, tzinfo=datetime.timezone(datetime.timedelta(hours=1))
    )
    assert attachment.checksum is None
    assert repr(attachment) == "<EmbeddedFile name='factur-x.xml'>"

    # No /Names in /Kids.
    names = reader.root_object[NameObject("/Names")]
    assert isinstance(names, DictionaryObject)

    files = names[NameObject("/EmbeddedFiles")]
    assert isinstance(files, DictionaryObject)

    kids = files[NameObject("/Kids")]
    assert isinstance(kids, ArrayObject)

    obj = kids[0].get_object()
    assert isinstance(obj, DictionaryObject)

    del obj[NameObject("/Names")]

    attachments = list(EmbeddedFile._load(reader.root_object))
    assert attachments == []


MALFORMED_NAME_TREE_CATALOGS = [
    pytest.param(
        DictionaryObject({NameObject("/Names"): NumberObject(1)}),
        id="names-tree-is-no-dictionary",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): NumberObject(1)}
            )}
        ),
        id="embedded-files-entry-is-no-dictionary",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Kids"): NumberObject(1)}
                )}
            )}
        ),
        id="kids-entry-is-no-array",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Kids"): ArrayObject([NumberObject(1)])}
                )}
            )}
        ),
        id="kid-is-no-dictionary",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Kids"): ArrayObject([DictionaryObject(
                        {NameObject("/Names"): NumberObject(1)}
                    )])}
                )}
            )}
        ),
        id="kid-name-list-is-no-array",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Names"): NumberObject(1)}
                )}
            )}
        ),
        id="name-list-is-no-array",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Names"): ArrayObject([TextStringObject("a.txt"), NumberObject(1)])}
                )}
            )}
        ),
        id="file-specification-is-no-dictionary",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Kids"): ArrayObject([DictionaryObject(
                        {NameObject("/Names"): ArrayObject([TextStringObject("a.txt"), NumberObject(1)])}
                    )])}
                )}
            )}
        ),
        id="kid-file-specification-is-no-dictionary",
    ),
]


@pytest.mark.parametrize("catalog", MALFORMED_NAME_TREE_CATALOGS)
def test_embedded_file__load_malformed_tree(catalog: DictionaryObject) -> None:
    # A malformed embedded files name tree must not crash attachment loading.
    assert list(EmbeddedFile._load(catalog)) == []


@pytest.mark.parametrize("catalog", MALFORMED_NAME_TREE_CATALOGS)
def test_embedded_file__load_malformed_tree__strict(catalog: DictionaryObject) -> None:
    # In strict mode, a malformed embedded files name tree raises instead.
    with pytest.raises(PdfReadError, match="is not a"):
        list(EmbeddedFile._load(catalog, strict=True))


SPEC_CONFORMANT_EMPTY_CATALOGS = [
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/Dests"): DictionaryObject()}
            )}
        ),
        id="no-embedded-files-entry",
    ),
    pytest.param(
        DictionaryObject({NameObject("/Names"): NullObject()}),
        id="null-names-tree",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): NullObject()}
            )}
        ),
        id="null-embedded-files-entry",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Kids"): NullObject()}
                )}
            )}
        ),
        id="null-kids-entry",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Kids"): ArrayObject([DictionaryObject(
                        {NameObject("/Names"): NullObject()}
                    )])}
                )}
            )}
        ),
        id="null-kid-name-list",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Names"): NullObject()}
                )}
            )}
        ),
        id="null-name-list",
    ),
    pytest.param(
        DictionaryObject(
            {NameObject("/Names"): DictionaryObject(
                {NameObject("/EmbeddedFiles"): DictionaryObject(
                    {NameObject("/Names"): ArrayObject([TextStringObject("a.txt"), NullObject()])}
                )}
            )}
        ),
        id="null-file-specification",
    ),
]


@pytest.mark.parametrize("catalog", SPEC_CONFORMANT_EMPTY_CATALOGS)
def test_embedded_file__load_absent_or_null_entries(
    catalog: DictionaryObject, caplog: pytest.LogCaptureFixture
) -> None:
    # A null value is equivalent to an omitted entry, thus neither warns nor raises.
    assert list(EmbeddedFile._load(catalog)) == []
    assert list(EmbeddedFile._load(catalog, strict=True)) == []
    assert caplog.text == ""


@pytest.mark.enable_socket
def test_embedded_file__ensure_params__existing_params() -> None:
    url = "https://github.com/user-attachments/files/18691309/embedded_files_kids.pdf"
    name = "embedded_files_kids.pdf"
    reader = PdfReader(BytesIO(get_data_from_url(url=url, name=name)))
    attachments = list(EmbeddedFile._load(reader.root_object))
    assert len(attachments) == 1
    attachment = attachments[0]

    assert "/Params" in attachment._embedded_file
    params_dict = attachment._ensure_params

    assert isinstance(params_dict, DictionaryObject)

    assert NameObject("/ModDate") in params_dict

    original_mod_date = params_dict.get(NameObject("/ModDate"))
    params_dict[NameObject("/TestParam")] = TextStringObject("test_value")

    assert params_dict[NameObject("/TestParam")] == TextStringObject("test_value")
    assert params_dict[NameObject("/ModDate")] == original_mod_date

    params_dict2 = attachment._ensure_params
    assert params_dict is params_dict2
    assert params_dict2[NameObject("/TestParam")] == TextStringObject("test_value")


def test_embedded_file__name_is_read_only() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    assert embedded_file.name == "test.txt"

    with pytest.raises(AttributeError):
        embedded_file.name = "new_name.txt"  # type: ignore[misc]


def test_embedded_file__alternative_name_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.alternative_name = TextStringObject("Alternative Name")
    assert embedded_file.alternative_name == "Alternative Name"

    embedded_file.alternative_name = None
    if NameObject("/UF") in embedded_file.pdf_object:
        assert embedded_file.pdf_object[NameObject("/UF")] == NullObject()
    if NameObject("/F") in embedded_file.pdf_object:
        assert embedded_file.pdf_object[NameObject("/F")] == NullObject()
    assert embedded_file.alternative_name is None

    pdf_string = TextStringObject("PDF String")
    embedded_file.alternative_name = pdf_string
    assert embedded_file.alternative_name == "PDF String"


def test_embedded_file__alternative_name__uf_key_only() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.pdf_object[NameObject("/UF")] = create_string_object("original_uf")
    del embedded_file.pdf_object[NameObject("/F")]

    assert NameObject("/UF") in embedded_file.pdf_object
    assert NameObject("/F") not in embedded_file.pdf_object

    embedded_file.alternative_name = None
    assert embedded_file.pdf_object[NameObject("/UF")] == NullObject()
    assert NameObject("/F") not in embedded_file.pdf_object

    embedded_file.alternative_name = TextStringObject("new_uf")
    assert embedded_file.pdf_object[NameObject("/UF")] == create_string_object("new_uf")
    assert embedded_file.pdf_object[NameObject("/F")] == create_string_object("new_uf")


def test_embedded_file__alternative_name__f_key_only() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.pdf_object[NameObject("/F")] = create_string_object("original_f")
    if NameObject("/UF") in embedded_file.pdf_object:
        del embedded_file.pdf_object[NameObject("/UF")]

    assert NameObject("/F") in embedded_file.pdf_object
    assert NameObject("/UF") not in embedded_file.pdf_object

    embedded_file.alternative_name = None
    assert embedded_file.pdf_object[NameObject("/F")] == NullObject()
    assert NameObject("/UF") not in embedded_file.pdf_object

    embedded_file.alternative_name = TextStringObject("new_f")
    assert embedded_file.pdf_object[NameObject("/F")] == create_string_object("new_f")
    assert embedded_file.pdf_object[NameObject("/UF")] == create_string_object("new_f")


def test_embedded_file__alternative_name__both_f_and_uf() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.pdf_object[NameObject("/F")] = create_string_object("original_f")
    embedded_file.pdf_object[NameObject("/UF")] = create_string_object("original_uf")

    embedded_file.alternative_name = TextStringObject("new_name")
    assert embedded_file.pdf_object[NameObject("/F")] == create_string_object("new_name")
    assert embedded_file.pdf_object[NameObject("/UF")] == create_string_object("new_name")
    assert embedded_file.alternative_name == "new_name"

    embedded_file.alternative_name = None
    assert embedded_file.pdf_object[NameObject("/F")] == NullObject()
    assert embedded_file.pdf_object[NameObject("/UF")] == NullObject()
    assert embedded_file.alternative_name is None


def test_embedded_file__description_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.description = TextStringObject("Test Description")
    assert embedded_file.description == "Test Description"

    embedded_file.description = None
    assert embedded_file.pdf_object[NameObject("/Desc")] == NullObject()

    pdf_string = TextStringObject("PDF Description")
    embedded_file.description = pdf_string
    assert embedded_file.description == "PDF Description"


def test_embedded_file__subtype_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.subtype = NameObject("/text/plain")
    assert embedded_file.subtype == "/text/plain"

    embedded_file.subtype = None
    assert embedded_file._embedded_file[NameObject("/Subtype")] == NullObject()

    name_obj = NameObject("/application#2Fjson")
    embedded_file.subtype = name_obj
    assert embedded_file.subtype == "/application#2Fjson"


def test_embedded_file__content_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")
    assert embedded_file.content == b"content"

    embedded_file.content = b"Hello World!"
    assert embedded_file.content == b"Hello World!"

    embedded_file.content = "Lorem ipsum dolor sit amet"
    assert embedded_file.content == b"Lorem ipsum dolor sit amet"


def test_embedded_file__size_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.size = NumberObject(1024)
    assert embedded_file.size == 1024

    embedded_file.size = None
    assert embedded_file._ensure_params[NameObject("/Size")] == NullObject()

    num_obj = NumberObject(2048)
    embedded_file.size = num_obj
    assert embedded_file.size == 2048


def test_embedded_file__size_getter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file._ensure_params[NameObject("/Size")] = NullObject()
    assert embedded_file.size is None

    embedded_file._ensure_params[NameObject("/Size")] = NumberObject(4096)
    retrieved_size = embedded_file.size
    assert retrieved_size == 4096


def test_embedded_file__creation_date_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    test_date = datetime.datetime(2023, 1, 1, 12, 0, 0)
    embedded_file.creation_date = test_date
    assert embedded_file.creation_date == test_date

    embedded_file.creation_date = None
    assert embedded_file._ensure_params[NameObject("/CreationDate")] == NullObject()


def test_embedded_file__modification_date_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    test_date = datetime.datetime(2023, 1, 2, 12, 0, 0)
    embedded_file.modification_date = test_date
    assert embedded_file.modification_date == test_date

    embedded_file.modification_date = None
    assert embedded_file._ensure_params[NameObject("/ModDate")] == NullObject()


def test_embedded_file__checksum_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    checksum_bytes = ByteStringObject(b"checksum_value")
    embedded_file.checksum = checksum_bytes
    assert embedded_file.checksum == b"checksum_value"

    embedded_file.checksum = None
    assert embedded_file._ensure_params[NameObject("/CheckSum")] == NullObject()

    byte_string = ByteStringObject(b"pdf_checksum")
    embedded_file.checksum = byte_string
    assert embedded_file.checksum == b"pdf_checksum"


def test_embedded_file__associated_file_relationship_setter() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.associated_file_relationship = NameObject("/Data")
    assert embedded_file.associated_file_relationship == "/Data"


def test_embedded_file__setters_integration() -> None:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)

    embedded_file = writer.add_attachment("test.txt", b"Hello, World!")
    embedded_file.alternative_name = TextStringObject("Alternative Name")
    embedded_file.description = TextStringObject("Test Description")
    embedded_file.subtype = NameObject("/text/plain")
    embedded_file.size = NumberObject(13)
    creation_date = datetime.datetime(2023, 1, 1, 12, 0, 0)
    embedded_file.creation_date = creation_date
    modification_date = datetime.datetime(2023, 1, 2, 12, 0, 0)
    embedded_file.modification_date = modification_date
    embedded_file.checksum = ByteStringObject(b"checksum123")
    embedded_file.associated_file_relationship = NameObject(AFRelationship.DATA)

    # Make sure that this is an indirect object for PDF/A-3 compliance.
    assert embedded_file.pdf_object.indirect_reference == IndirectObject(6, 0, writer)

    pdf_bytes = BytesIO()
    writer.write(pdf_bytes)

    reader = PdfReader(pdf_bytes)
    assert "test.txt" in reader.attachments


def test_embedded_file__null_object_handling() -> None:
    writer = PdfWriter()
    embedded_file = writer.add_attachment("test.txt", b"content")

    embedded_file.alternative_name = TextStringObject("Name")
    embedded_file.description = TextStringObject("Description")
    embedded_file.subtype = NameObject("/text/plain")
    embedded_file.size = NumberObject(1024)
    embedded_file.checksum = ByteStringObject(b"checksum")

    embedded_file.alternative_name = None
    embedded_file.description = None
    embedded_file.subtype = None
    embedded_file.size = None
    embedded_file.checksum = None

    assert embedded_file.alternative_name is None
    assert embedded_file.description is None
    assert embedded_file.subtype is None
    assert embedded_file.size is None
    assert embedded_file.checksum is None


def test_embedded_file__delete_without_parent() -> None:
    attachment = EmbeddedFile(name="test.txt", pdf_object=DictionaryObject())
    with pytest.raises(PyPdfError, match=r"^Parent required to delete file from document\.$"):
        attachment.delete()


def test_embedded_file__delete_known() -> None:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    attachment = writer.add_attachment("test.txt", b"content")
    writer.add_attachment("test2.txt", b"content2")

    attachments = list(writer.attachment_list)
    assert len(attachments) == 2
    attachment.delete()
    with pytest.raises(PdfReadError, match=r"^/EF entry not found: {}$"):
        _ = attachment.content

    attachments = list(writer.attachment_list)
    assert len(attachments) == 1
    assert attachments[0].name == "test2.txt"

    # Delete second time.
    with pytest.raises(PyPdfError, match=r"^File not found in parent object\.$"):
        attachment.delete()


def test_embedded_file__delete__no_indirect_reference() -> None:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)

    # Add an attachment and replace the indirect reference in the name tree
    # by the dictionary itself. This is how pypdf <= 6.1.0 would embed files
    # and thus should be supported as well.
    embedded_file = writer.add_attachment("test.txt", b"Hello, World!")
    assert embedded_file.pdf_object.indirect_reference == IndirectObject(6, 0, writer)
    assert embedded_file._parent is not None
    embedded_file._parent[-1] = embedded_file.pdf_object.get_object()

    embedded_file.delete()
    attachments = list(writer.attachment_list)
    assert len(attachments) == 0


@pytest.mark.enable_socket
def test_embedded_file__create__kids_based_name_tree() -> None:
    """Test for issue #3473."""
    url = "https://github.com/user-attachments/files/18691309/embedded_files_kids.pdf"
    name = "embedded_files_kids.pdf"
    writer = PdfWriter(clone_from=BytesIO(get_data_from_url(url=url, name=name)))

    writer.add_attachment("test.pdf", b"content")

    assert dict(writer.attachments) == {
        "factur-x.xml": [
            (
                b"Hello World!\n\nLorem ipsum dolor sit amet, consetetur sad"
                b"ipscing elitr, sed diam nonumy eirmod tempor\ninvidunt ut"
                b" labore et dolore magna aliquyam erat, sed diam voluptua"
                b". At vero eos et accusam\net justo duo dolores et ea rebu"
                b"m. Stet clita kasd gubergren, no sea takimata sanctus es"
                b"t Lorem\nipsum dolor sit amet. Lorem ipsum dolor sit amet"
                b", consetetur sadipscing elitr, sed diam\nnonumy eirmod te"
                b"mpor invidunt ut labore et dolore magna aliquyam erat, s"
                b"ed diam voluptua.\nAt vero eos et accusam et justo duo do"
                b"lores et ea rebum. Stet clita kasd gubergren, no sea\ntak"
                b"imata sanctus est Lorem ipsum dolor sit amet.\n"
            )
        ],
        "test.pdf": [b"content"]
    }

    attachments = list(writer.attachment_list)
    assert len(attachments) == 2

    names = writer.root_object["/Names"]
    assert isinstance(names, DictionaryObject)

    embedded = names["/EmbeddedFiles"]
    assert isinstance(embedded, DictionaryObject)

    result = embedded["/Names"]
    assert result == [  # type: ignore[comparison-overlap]
        "factur-x.xml",
        attachments[0].pdf_object.indirect_reference,
        "test.pdf",
        attachments[1].pdf_object.indirect_reference
    ]


def test_embedded_file__create__neither_kids_nor_names() -> None:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)

    # Add an attachment and remove the corresponding /Names key.
    writer.add_attachment("test.txt", b"Hello, World!")
    names = writer.root_object["/Names"]
    assert isinstance(names, DictionaryObject)
    files = names["/EmbeddedFiles"]
    assert isinstance(files, DictionaryObject)

    del files["/Names"]

    with pytest.raises(expected_exception=PdfReadError, match=r"^Got neither Names nor Kids in embedded files tree\.$"):
        writer.add_attachment("test2.txt", b"content2")


def test_embedded_file__get_insertion_index() -> None:
    # Empty list.
    assert EmbeddedFile._get_insertion_index(ArrayObject(), "test.txt") == 0

    # One mismatching entry.
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("dummy.txt"), NullObject()]),
        "test.txt"
    ) == 2
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("xxx.txt"), NullObject()]),
        "test.txt"
    ) == 0

    # Multiple entries.
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("dummy.txt"), NullObject(), TextStringObject("xxx.txt"), NullObject()]),
        "test.txt"
    ) == 2
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("xxx.txt"), NullObject(), TextStringObject("yyy.txt"), NullObject()]),
        "test.txt"
    ) == 0
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("aaa.txt"), NullObject(), TextStringObject("bbb.txt"), NullObject()]),
        "test.txt"
    ) == 4
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([
            TextStringObject("aaa.txt"), NullObject(),
            TextStringObject("test.txt"), NullObject(),
            TextStringObject("zzz.txt"), NullObject()
        ]),
        "test.txt"
    ) == 4

    # Length.
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("a"), NullObject()]),
        "aa"
    ) == 2
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("a"), NullObject()]),
        "a"
    ) == 2
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("aaa"), NullObject()]),
        "aa"
    ) == 0

    # Special characters.
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("café"), NullObject()]),
        "cafe"
    ) == 0
    assert EmbeddedFile._get_insertion_index(
        ArrayObject([TextStringObject("Tun"), NullObject()]),
        "Tür"
    ) == 2


def test_embedded_file__order() -> None:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)

    attachment1 = writer.add_attachment("test.txt", "content")
    attachment2 = writer.add_attachment("abc.txt", "content")
    attachment3 = writer.add_attachment("xyz.txt", "content")
    attachment4 = writer.add_attachment("test.txt", "content2")

    assert dict(writer.attachments) == {
        "abc.txt": [b"content"],
        "test.txt": [b"content", b"content2"],
        "xyz.txt": [b"content"]
    }
    names = writer.root_object["/Names"]
    assert isinstance(names, DictionaryObject)
    files = names["/EmbeddedFiles"]
    assert isinstance(files, DictionaryObject)
    assert files["/Names"] == [  # type: ignore[comparison-overlap]
        "abc.txt", attachment2.pdf_object.indirect_reference,
        "test.txt", attachment1.pdf_object.indirect_reference,
        "test.txt", attachment4.pdf_object.indirect_reference,
        "xyz.txt", attachment3.pdf_object.indirect_reference,
    ]


def _roundtrip(writer: PdfWriter) -> PdfReader:
    buffer = BytesIO()
    writer.write(buffer)
    return PdfReader(BytesIO(buffer.getvalue()))


def test_embedded_file__same_name_different_content_is_stable() -> None:
    # Two actual files sharing one name must both survive enumeration and be
    # distinguishable through their content digests.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    first = writer.add_attachment("same.txt", b"first content")
    second = writer.add_attachment("same.txt", b"second content")

    reader = _roundtrip(writer)
    entries = list(reader.attachment_list)
    assert len(entries) == 2
    assert [entry.name for entry in entries] == ["same.txt", "same.txt"]
    assert [entry.content for entry in entries] == [b"first content", b"second content"]

    digests = {entry.sha256 for entry in entries}
    assert digests == {
        hashlib.sha256(b"first content").hexdigest(),
        hashlib.sha256(b"second content").hexdigest(),
    }
    for entry in entries:
        assert entry.md5 == hashlib.md5(entry.content).hexdigest()
        assert entry.content_digest("sha1") == hashlib.sha1(entry.content).hexdigest()

    # The legacy name-based lookup keeps every payload, in name tree order.
    assert reader.attachments["same.txt"] == [b"first content", b"second content"]
    # The underlying objects remain independently addressable.
    assert first.pdf_object is not second.pdf_object


def test_embedded_file__name_tree_sources() -> None:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.add_attachment("test.txt", b"content")

    reader = _roundtrip(writer)
    entry = next(iter(reader.attachment_list))
    assert len(entry.sources) == 1
    source = entry.sources[0]
    assert source.kind == AttachmentSource.NAME_TREE
    assert source.location == "/Names/EmbeddedFiles/Names[0]"
    assert source.name == "test.txt"
    assert repr(source) == (
        "AttachmentSource(kind='name_tree', "
        "location='/Names/EmbeddedFiles/Names[0]', name='test.txt')"
    )


def test_embedded_file__uf_differs_from_tree_key() -> None:
    # The name tree key stays the primary name; /UF is the alternative name.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    attachment = writer.add_attachment("tree-name.txt", b"content")
    attachment.pdf_object[NameObject("/UF")] = create_string_object("unicode-name.txt")

    reader = _roundtrip(writer)
    entry = next(iter(reader.attachment_list))
    assert entry.name == "tree-name.txt"
    assert entry.alternative_name == "unicode-name.txt"
    assert entry.sources[0].name == "tree-name.txt"
    # Both names resolve through the legacy mapping.
    assert set(reader.attachments) == {"tree-name.txt", "unicode-name.txt"}


def test_embedded_file__same_object_merged_across_references() -> None:
    # One file specification object reachable from the name tree, the catalog
    # /AF array and a page /AF array is reported once with three sources.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    attachment = writer.add_attachment("shared.txt", b"shared payload")
    reference = attachment.pdf_object.indirect_reference
    writer.root_object[NameObject("/AF")] = ArrayObject([reference])
    writer.pages[0][NameObject("/AF")] = ArrayObject([reference])

    reader = _roundtrip(writer)
    entries = list(reader.attachment_list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.content == b"shared payload"
    locations = {source.location: source.kind for source in entry.sources}
    assert locations == {
        "/Names/EmbeddedFiles/Names[0]": AttachmentSource.NAME_TREE,
        "/AF[0]": AttachmentSource.ASSOCIATED_FILE,
        "/Pages[0]/AF[0]": AttachmentSource.ASSOCIATED_FILE,
    }
    # Each name-based lookup still returns the single shared payload.
    assert reader.attachments["shared.txt"] == [b"shared payload"]


def test_embedded_file__catalog_associated_file_without_name_tree() -> None:
    # An /AF-only file must not be invisible just because it has no name tree key.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    attachment = writer.add_attachment("af-only.txt", b"associated payload")
    reference = attachment.pdf_object.indirect_reference
    del writer.root_object["/Names"]["/EmbeddedFiles"]["/Names"][:]
    writer.root_object[NameObject("/AF")] = ArrayObject([reference])

    reader = _roundtrip(writer)
    # The name-tree-only helper keeps its historical, narrower scope.
    assert list(EmbeddedFile._load(reader.root_object)) == []

    entries = list(reader.attachment_list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.name == "af-only.txt"
    assert entry.sources == (
        AttachmentSource(
            kind=AttachmentSource.ASSOCIATED_FILE,
            location="/AF[0]",
            name="af-only.txt",
        ),
    )
    assert reader.attachments["af-only.txt"] == [b"associated payload"]


def test_embedded_file__file_attachment_annotation() -> None:
    # resources/attachment.pdf only references its embedded file through an
    # annotation /FS entry, which the old enumeration missed completely.
    reader = PdfReader(RESOURCE_ROOT / "attachment.pdf")
    assert list(EmbeddedFile._load(reader.root_object)) == []

    entries = list(reader.attachment_list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.name == "jpeg.pdf"
    assert entry.sources == (
        AttachmentSource(
            kind=AttachmentSource.ASSOCIATED_FILE,
            location="/Pages[0]/Annots[0]/FS",
            name="jpeg.pdf",
        ),
    )
    assert len(entry.content) == 100898
    assert "jpeg.pdf" in reader.attachments


def test_embedded_file__associated_file_malformed_entries() -> None:
    catalogs = [
        DictionaryObject({NameObject("/AF"): NumberObject(1)}),
        DictionaryObject({NameObject("/AF"): ArrayObject([NumberObject(7)])}),
        DictionaryObject({NameObject("/AF"): ArrayObject([NullObject()])}),
    ]
    for catalog in catalogs:
        writer = PdfWriter()
        writer._root_object = catalog
        assert list(EmbeddedFile._load_all(writer)) == []

    writer = PdfWriter()
    writer._root_object = catalogs[0]
    with pytest.raises(PdfReadError, match="is not an array"):
        list(EmbeddedFile._load_all(writer, strict=True))

    writer = PdfWriter()
    writer._root_object = catalogs[1]
    with pytest.raises(PdfReadError, match="is not a dictionary"):
        list(EmbeddedFile._load_all(writer, strict=True))


def test_embedded_file__missing_ef_is_enumerated_lazily() -> None:
    # A file specification without an /EF stream still appears in the list;
    # the damage surfaces only when its content is requested.
    file_specification = DictionaryObject(
        {NameObject("/F"): TextStringObject("no-ef.bin")}
    )
    writer = PdfWriter()
    writer._root_object = DictionaryObject(
        {NameObject("/AF"): ArrayObject([file_specification])}
    )

    entries = list(EmbeddedFile._load_all(writer))
    assert len(entries) == 1
    assert entries[0].name == "no-ef.bin"
    with pytest.raises(PdfReadError, match="/EF entry not found"):
        _ = entries[0].content
    with pytest.raises(PdfReadError, match="/EF entry not found"):
        _ = entries[0].sha256


def test_embedded_file__nested_kids_source_location() -> None:
    file_specification = DictionaryObject(
        {NameObject("/F"): TextStringObject("nested.txt")}
    )
    inner = DictionaryObject(
        {NameObject("/Names"): ArrayObject([TextStringObject("nested.txt"), file_specification])}
    )
    outer = DictionaryObject({NameObject("/Kids"): ArrayObject([inner])})
    catalog = DictionaryObject(
        {NameObject("/Names"): DictionaryObject(
            {NameObject("/EmbeddedFiles"): outer}
        )}
    )
    writer = PdfWriter()
    writer._root_object = catalog

    entries = list(EmbeddedFile._load_all(writer))
    assert len(entries) == 1
    assert entries[0].sources[0].location == "/Names/EmbeddedFiles/Kids[0]/Names[0]"


def test_embedded_file__cyclic_name_tree_does_not_hang() -> None:
    cyclic = DictionaryObject()
    cyclic[NameObject("/Kids")] = ArrayObject([cyclic])
    catalog = DictionaryObject(
        {NameObject("/Names"): DictionaryObject(
            {NameObject("/EmbeddedFiles"): cyclic}
        )}
    )
    writer = PdfWriter()
    writer._root_object = catalog

    assert list(EmbeddedFile._load_all(writer)) == []
    with pytest.raises(PdfReadError, match="cycle"):
        list(EmbeddedFile._load_all(writer, strict=True))


def test_embedded_file__odd_name_list() -> None:
    catalog = DictionaryObject(
        {NameObject("/Names"): DictionaryObject(
            {NameObject("/EmbeddedFiles"): DictionaryObject(
                {NameObject("/Names"): ArrayObject([TextStringObject("lonely.txt")])}
            )}
        )}
    )
    writer = PdfWriter()
    writer._root_object = catalog
    assert list(EmbeddedFile._load_all(writer)) == []
    with pytest.raises(PdfReadError, match="odd number of elements"):
        list(EmbeddedFile._load_all(writer, strict=True))


def test_embedded_file__annotation_associated_files() -> None:
    # An annotation can carry associated files itself through /AF.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    file_specification = DictionaryObject(
        {NameObject("/F"): TextStringObject("ann-af.bin")}
    )
    annotation = DictionaryObject(
        {
            NameObject("/Subtype"): NameObject("/Stamp"),
            NameObject("/AF"): ArrayObject([writer._add_object(file_specification)]),
        }
    )
    writer.pages[0][NameObject("/Annots")] = ArrayObject(
        [writer._add_object(annotation)]
    )

    reader = _roundtrip(writer)
    entries = list(reader.attachment_list)
    assert len(entries) == 1
    assert entries[0].sources == (
        AttachmentSource(
            kind=AttachmentSource.ASSOCIATED_FILE,
            location="/Pages[0]/Annots[0]/AF[0]",
            name="ann-af.bin",
        ),
    )


def test_embedded_file__non_string_name_entries() -> None:
    # Non-string /F entries must not break enumeration or the name mapping.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    stream = DecodedStreamObject()
    stream.set_data(b"two")
    stream[NameObject("/Type")] = NameObject("/EmbeddedFile")
    file_specification = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Filespec"),
            NameObject("/F"): NumberObject(7),
            NameObject("/EF"): DictionaryObject(
                {NameObject("/F"): writer._add_object(stream)}
            ),
        }
    )
    writer.root_object[NameObject("/AF")] = ArrayObject(
        [writer._add_object(file_specification)]
    )

    reader = _roundtrip(writer)
    entries = list(reader.attachment_list)
    assert len(entries) == 1
    assert entries[0].name == ""
    assert entries[0].sources[0].name is None
    # A file without any usable name is simply absent from the name mapping.
    assert dict(reader.attachments) == {}
    assert entries[0].content == b"two"


def test_embedded_file__sources_of_writer_attachments() -> None:
    # The writer benefits from the same enumeration as the reader.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.add_attachment("a.txt", b"a")
    writer.add_attachment("b.txt", b"b")

    entries = list(writer.attachment_list)
    assert [entry.name for entry in entries] == ["a.txt", "b.txt"]
    assert [entry.sources[0].location for entry in entries] == [
        "/Names/EmbeddedFiles/Names[0]",
        "/Names/EmbeddedFiles/Names[2]",
    ]


def test_embedded_file__same_object_under_two_name_tree_keys() -> None:
    # One object registered twice in the name tree is enumerated once while
    # both keys remain visible in the sources and the legacy name mapping.
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    attachment = writer.add_attachment("first.txt", b"data")
    names = writer.root_object["/Names"]["/EmbeddedFiles"]["/Names"]
    names.append(TextStringObject("second.txt"))
    names.append(attachment.pdf_object.indirect_reference)

    reader = _roundtrip(writer)
    entries = list(reader.attachment_list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.name == "first.txt"
    assert [source.name for source in entry.sources] == ["first.txt", "second.txt"]
    assert [source.location for source in entry.sources] == [
        "/Names/EmbeddedFiles/Names[0]",
        "/Names/EmbeddedFiles/Names[2]",
    ]
    assert set(reader.attachments) == {"first.txt", "second.txt"}
    assert reader.attachments["second.txt"] == [b"data"]
