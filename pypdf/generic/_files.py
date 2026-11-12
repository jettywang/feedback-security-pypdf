from __future__ import annotations

import bisect
import hashlib
from functools import cached_property
from typing import TYPE_CHECKING, NamedTuple, cast

from pypdf._utils import format_iso8824_date, logger_warning, parse_iso8824_date
from pypdf.constants import CatalogAttributes as CA
from pypdf.constants import FileSpecificationDictionaryEntries
from pypdf.constants import PageAttributes as PG
from pypdf.errors import PdfReadError, PyPdfError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NullObject,
    NumberObject,
    PdfObject,
    StreamObject,
    TextStringObject,
    is_null_or_none,
)

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator

    from pypdf._doc_common import PdfDocCommon
    from pypdf._writer import PdfWriter


class AttachmentSource(NamedTuple):
    """
    A single place from which an embedded file is referenced.

    One :class:`EmbeddedFile` can be reachable from several places, for example
    because the same file specification object is listed in the embedded files
    name tree and in an associated files (``/AF``) array, or because a malformed
    document registers it under several name tree keys.

    Attributes:
        kind: How the file is referenced. One of :data:`AttachmentSource.NAME_TREE`
            and :data:`AttachmentSource.ASSOCIATED_FILE`.
        location: Where the reference lives, as a slash-separated path of PDF
            dictionary keys and array indices, e.g.
            ``/Names/EmbeddedFiles/Names[0]`` or
            ``/Pages[0]/Annots[0]/FS``.
        name: The name used at this reference, if any. For name tree entries
            this is the name tree key; for associated file references it is the
            ``/UF`` or ``/F`` name of the file specification dictionary. It is
            ``None`` when the reference does not carry a name.
    """

    NAME_TREE = "name_tree"
    ASSOCIATED_FILE = "associated_file"

    kind: str
    location: str
    name: str | None

    def __repr__(self) -> str:
        return f"AttachmentSource(kind={self.kind!r}, location={self.location!r}, name={self.name!r})"


class EmbeddedFile:
    """
    Container holding the information on an embedded file.

    Attributes are evaluated lazily if possible.

    Further information on embedded files can be found in section 7.11 of the PDF 2.0 specification.
    """
    def __init__(
        self,
        name: str,
        pdf_object: DictionaryObject,
        parent: ArrayObject | None = None,
        sources: list[AttachmentSource] | None = None,
    ) -> None:
        """
        Args:
            name: The (primary) name as provided in the name tree or the file
                specification dictionary.
            pdf_object: The corresponding PDF object to allow retrieving further data.
            parent: The parent list.
            sources: The references through which this file is reachable.
        """
        self._name = name
        self.pdf_object = pdf_object
        self._parent = parent
        self._sources: list[AttachmentSource] = list(sources) if sources else []

    @property
    def name(self) -> str:
        """
        The (primary) name of the embedded file.

        It is the name tree key when the file is registered in the embedded files
        name tree. Files only referenced through an associated files (``/AF``)
        array or a file attachment annotation fall back to the ``/UF`` or ``/F``
        entry of their file specification dictionary.

        .. warning::

            This value can contain arbitrary characters. Please make sure to sanitize it before
            using it to write the file content to the disk for example.
        """
        return self._name

    @property
    def sources(self) -> tuple[AttachmentSource, ...]:
        """
        All references through which this embedded file is reachable.

        Each entry pinpoints a location of the document - an embedded files
        name tree entry or an associated files (``/AF``) reference, including
        those used by file attachment annotations - and records the name used
        there. A file that is referenced several times (for example because the
        same object appears in the name tree and in an ``/AF`` array) reports
        one source per reference.
        """
        return tuple(self._sources)

    def content_digest(self, algorithm: str = "sha256") -> str:
        """
        Compute a checksum of the decoded file content.

        This allows callers to tell attachments with the same name but
        different content apart without comparing the (potentially large)
        payloads themselves. The checksum is computed on demand and is not
        cached, so this only reads data that is actually requested.

        Args:
            algorithm: A hash algorithm name accepted by
                :func:`hashlib.new`, such as ``"sha256"`` (the default) or
                ``"md5"``.

        Returns:
            The hexadecimal digest of :attr:`content`.
        """
        return hashlib.new(algorithm, self.content).hexdigest()

    @property
    def sha256(self) -> str:
        """The SHA-256 hexadecimal digest of the decoded file content."""
        return self.content_digest("sha256")

    @property
    def md5(self) -> str:
        """The MD5 hexadecimal digest of the decoded file content."""
        return self.content_digest("md5")

    @classmethod
    def _create_new(cls, writer: PdfWriter, name: str, content: str | bytes) -> EmbeddedFile:
        """
        Create a new embedded file and add it to the PdfWriter.

        Args:
            writer: The PdfWriter instance to add the embedded file to.
            name: The filename to display.
            content: The data in the file.

        Returns:
            EmbeddedFile instance for the newly created embedded file.
        """
        # Convert string content to bytes if needed
        if isinstance(content, str):
            content = content.encode("latin-1")

        # Create the file entry (the actual embedded file stream)
        file_entry = DecodedStreamObject()
        file_entry.set_data(content)
        file_entry.update({NameObject(PG.TYPE): NameObject("/EmbeddedFile")})

        # Create the /EF entry
        ef_entry = DictionaryObject()
        ef_entry.update({NameObject("/F"): writer._add_object(file_entry)})

        # Create the filespec dictionary
        from pypdf.generic import create_string_object  # noqa: PLC0415
        filespec = DictionaryObject()
        filespec_reference = writer._add_object(filespec)
        name_object = cast(TextStringObject, create_string_object(name))
        filespec.update(
            {
                NameObject(PG.TYPE): NameObject("/Filespec"),
                NameObject(FileSpecificationDictionaryEntries.F): name_object,
                NameObject(FileSpecificationDictionaryEntries.EF): ef_entry,
            }
        )

        # Add the name and filespec to the names array.
        # We use the inverse order for insertion, as this allows us to re-use the
        # same index.
        names_array = cls._get_names_array(writer)
        insertion_index = cls._get_insertion_index(names_array, name_object)
        names_array.insert(insertion_index, filespec_reference)
        names_array.insert(insertion_index, name_object)

        # Return an EmbeddedFile instance
        return cls(name=name, pdf_object=filespec, parent=names_array)

    @classmethod
    def _get_names_array(cls, writer: PdfWriter) -> ArrayObject:
        """Get the names array for embedded files, possibly creating and flattening it."""
        if CA.NAMES not in writer.root_object:
            # Add the /Names entry to the catalog.
            writer.root_object[NameObject(CA.NAMES)] = writer._add_object(DictionaryObject())

        names_dict = cast(DictionaryObject, writer.root_object[CA.NAMES])
        if "/EmbeddedFiles" not in names_dict:
            # We do not yet have an entry for embedded files. Create and return it.
            names = ArrayObject()
            embedded_files_names_dictionary = DictionaryObject(
                {NameObject(CA.NAMES): names}
            )
            names_dict[NameObject("/EmbeddedFiles")] = writer._add_object(embedded_files_names_dictionary)
            return names

        # We have an existing embedded files entry.
        embedded_files_names_tree = cast(DictionaryObject, names_dict["/EmbeddedFiles"])
        if "/Names" in embedded_files_names_tree:
            # Simple case: We already have a flat list.
            return cast(ArrayObject, embedded_files_names_tree[NameObject(CA.NAMES)])
        if "/Kids" not in embedded_files_names_tree:
            # Invalid case: This is no name tree.
            raise PdfReadError("Got neither Names nor Kids in embedded files tree.")

        # Complex case: Convert a /Kids-based name tree to a /Names-based one.
        # /Name-based ones are much easier to handle and allow us to simplify the
        # actual insertion logic by only having to consider one case.
        names = ArrayObject()
        kids = cast(ArrayObject, embedded_files_names_tree["/Kids"].get_object())
        embedded_files_names_dictionary = DictionaryObject(
            {NameObject(CA.NAMES): names}
        )
        names_dict[NameObject("/EmbeddedFiles")] = writer._add_object(embedded_files_names_dictionary)
        for kid in kids:
            # Write the flattened file entries. As we do not change the actual files,
            # this should not have any impact on references to them.
            # There might be further (nested) kids here.
            # Wait for an example before evaluating an implementation.
            for name in kid.get_object().get("/Names", []):
                names.append(name)
        return names

    @classmethod
    def _get_insertion_index(cls, names_array: ArrayObject, name: str) -> int:
        keys = [names_array[i].encode("utf-8") for i in range(0, len(names_array), 2)]
        name_bytes = name.encode("utf-8")

        start = bisect.bisect_left(keys, name_bytes)
        end = bisect.bisect_right(keys, name_bytes)

        if start != end:
            return end * 2
        if start == 0:
            return 0
        if start == (key_count := len(keys)):
            return key_count * 2
        return end * 2

    @property
    def alternative_name(self) -> str | None:
        """
        Retrieve the alternative name (as per the file specification dictionary).

        .. warning::

            This value can contain arbitrary characters. Please make sure to sanitize it before
            using it to write the file content to the disk for example.
        """
        for key in [FileSpecificationDictionaryEntries.UF, FileSpecificationDictionaryEntries.F]:
            # PDF 2.0 reference, table 43:
            #   > A PDF reader shall use the value of the UF key, when present, instead of the F key.
            if key in self.pdf_object:
                value = self.pdf_object[key].get_object()
                if isinstance(value, (str, bytes)):
                    return str(value)
        return None

    @alternative_name.setter
    def alternative_name(self, value: TextStringObject | None) -> None:
        """Set the alternative name (as per the file specification dictionary)."""
        if value is None:
            if FileSpecificationDictionaryEntries.UF in self.pdf_object:
                self.pdf_object[NameObject(FileSpecificationDictionaryEntries.UF)] = NullObject()
            if FileSpecificationDictionaryEntries.F in self.pdf_object:
                self.pdf_object[NameObject(FileSpecificationDictionaryEntries.F)] = NullObject()
        else:
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.UF)] = value
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.F)] = value

    @property
    def description(self) -> str | None:
        """Retrieve the description."""
        value = self.pdf_object.get(FileSpecificationDictionaryEntries.DESC)
        if is_null_or_none(value):
            return None
        return value

    @description.setter
    def description(self, value: TextStringObject | None) -> None:
        """Set the description."""
        if value is None:
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.DESC)] = NullObject()
        else:
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.DESC)] = value

    @property
    def associated_file_relationship(self) -> str:
        """Retrieve the relationship of the referring document to this embedded file."""
        return cast(
            NameObject,
            self.pdf_object.get("/AFRelationship", NameObject("/Unspecified")),
        )

    @associated_file_relationship.setter
    def associated_file_relationship(self, value: NameObject) -> None:
        """Set the relationship of the referring document to this embedded file."""
        self.pdf_object[NameObject("/AFRelationship")] = value

    @property
    def _embedded_file(self) -> StreamObject:
        """Retrieve the actual embedded file stream."""
        if "/EF" not in self.pdf_object:
            raise PdfReadError(f"/EF entry not found: {self.pdf_object}")
        ef = cast(DictionaryObject, self.pdf_object["/EF"])
        for key in [FileSpecificationDictionaryEntries.UF, FileSpecificationDictionaryEntries.F]:
            if key in ef:
                return cast(StreamObject, ef[key].get_object())
        raise PdfReadError(f"No /(U)F key found in file dictionary: {ef}")

    @property
    def _params(self) -> DictionaryObject:
        """Retrieve the file-specific parameters."""
        return cast(DictionaryObject, self._embedded_file.get("/Params", DictionaryObject()).get_object())

    @cached_property
    def _ensure_params(self) -> DictionaryObject:
        """Ensure the /Params dictionary exists and return it."""
        embedded_file = self._embedded_file
        if "/Params" not in embedded_file:
            embedded_file[NameObject("/Params")] = DictionaryObject()
        return cast(DictionaryObject, embedded_file["/Params"])

    @property
    def subtype(self) -> str | None:
        """Retrieve the subtype. This is a MIME media type, prefixed by a slash."""
        value = self._embedded_file.get("/Subtype")
        if is_null_or_none(value):
            return None
        return value

    @subtype.setter
    def subtype(self, value: NameObject | None) -> None:
        """Set the subtype. This should be a MIME media type, prefixed by a slash."""
        embedded_file = self._embedded_file
        if value is None:
            embedded_file[NameObject("/Subtype")] = NullObject()
        else:
            embedded_file[NameObject("/Subtype")] = value

    @property
    def content(self) -> bytes:
        """Retrieve the actual file content."""
        return self._embedded_file.get_data()

    @content.setter
    def content(self, value: str | bytes) -> None:
        """Set the file content."""
        if isinstance(value, str):
            value = value.encode("latin-1")
        self._embedded_file.set_data(value)

    @property
    def size(self) -> int | None:
        """Retrieve the size of the uncompressed file in bytes."""
        value = self._params.get("/Size")
        if is_null_or_none(value):
            return None
        return value

    @size.setter
    def size(self, value: NumberObject | None) -> None:
        """Set the size of the uncompressed file in bytes."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/Size")] = NullObject()
        else:
            params[NameObject("/Size")] = value

    @property
    def creation_date(self) -> datetime.datetime | None:
        """Retrieve the file creation datetime."""
        return parse_iso8824_date(self._params.get("/CreationDate"))

    @creation_date.setter
    def creation_date(self, value: datetime.datetime | None) -> None:
        """Set the file creation datetime."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/CreationDate")] = NullObject()
        else:
            date_str = format_iso8824_date(value)
            params[NameObject("/CreationDate")] = TextStringObject(date_str)

    @property
    def modification_date(self) -> datetime.datetime | None:
        """Retrieve the datetime of the last file modification."""
        return parse_iso8824_date(self._params.get("/ModDate"))

    @modification_date.setter
    def modification_date(self, value: datetime.datetime | None) -> None:
        """Set the datetime of the last file modification."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/ModDate")] = NullObject()
        else:
            date_str = format_iso8824_date(value)
            params[NameObject("/ModDate")] = TextStringObject(date_str)

    @property
    def checksum(self) -> bytes | None:
        """Retrieve the MD5 checksum of the (uncompressed) file."""
        value = self._params.get("/CheckSum")
        if is_null_or_none(value):
            return None
        return value

    @checksum.setter
    def checksum(self, value: ByteStringObject | None) -> None:
        """Set the MD5 checksum of the (uncompressed) file."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/CheckSum")] = NullObject()
        else:
            params[NameObject("/CheckSum")] = value

    @property
    def _names(self) -> Iterator[str]:
        yield self.name
        if self.alternative_name is not None and self.alternative_name != self.name:
            yield self.alternative_name

    def delete(self) -> None:
        """Delete the file from the document."""
        if not self._parent:
            raise PyPdfError("Parent required to delete file from document.")
        if self.pdf_object in self._parent:
            index = self._parent.index(self.pdf_object)
        elif (
                (indirect_reference := getattr(self.pdf_object, "indirect_reference", None)) is not None
                and indirect_reference in self._parent
        ):
            index = self._parent.index(indirect_reference)
        else:
            raise PyPdfError("File not found in parent object.")
        self._parent.pop(index)  # Reference.
        self._parent.pop(index - 1)  # Name.
        self.pdf_object = DictionaryObject()  # Invalidate.

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

    @staticmethod
    def _report_malformed(message: str, strict: bool) -> None:
        """Raise an exception in strict mode, warn otherwise."""
        if strict:
            raise PdfReadError(message)
        logger_warning(message, source=__name__)

    #: Maximum nesting depth of an embedded files name tree, independently of
    #: the configuration limits, as a safeguard against cyclic references.
    _NAME_TREE_MAXIMUM_DEPTH = 100

    @classmethod
    def _iter_name_tree(
        cls,
        node: DictionaryObject,
        *,
        base_location: str,
        strict: bool,
        visited: set[int] | None = None,
        depth: int = 0,
    ) -> Iterator[tuple[ArrayObject, str, int]]:
        """
        Walk an embedded files name tree and yield
        ``(names_array, location, key_index)`` triples, one for every
        ``key, value`` pair stored in a ``/Names`` array.

        ``key_index`` is the position of the name key inside ``names_array``;
        the associated value follows at ``key_index + 1``. ``base_location`` is
        the path of the tree root dictionary; array indices are appended so
        that each yielded pair carries its exact location.
        """
        if visited is None:
            visited = set()
        if depth > cls._NAME_TREE_MAXIMUM_DEPTH:
            cls._report_malformed(
                f"Embedded files name tree exceeds the maximum depth of "
                f"{cls._NAME_TREE_MAXIMUM_DEPTH}.",
                strict=strict,
            )
            return
        node_id = id(node)
        if node_id in visited:
            cls._report_malformed("Detected a cycle in the embedded files name tree.", strict=strict)
            return
        visited.add(node_id)

        if "/Kids" in node:
            kids = node["/Kids"].get_object()
            if isinstance(kids, NullObject):
                kids = ArrayObject()
            elif not isinstance(kids, ArrayObject):
                cls._report_malformed(f"Embedded files /Kids is not an array: {kids}", strict=strict)
                return
            for index, kid in enumerate(kids):
                kid_object = kid.get_object()
                if not isinstance(kid_object, DictionaryObject):
                    cls._report_malformed(
                        f"Embedded files kid is not a dictionary: {kid_object}", strict=strict
                    )
                    continue
                yield from cls._iter_name_tree(
                    kid_object,
                    base_location=f"{base_location}/Kids[{index}]",
                    strict=strict,
                    visited=visited,
                    depth=depth + 1,
                )
        if "/Names" in node:
            names = node["/Names"].get_object()
            if isinstance(names, NullObject):
                return
            if not isinstance(names, ArrayObject):
                cls._report_malformed(f"Embedded files name list is not an array: {names}", strict=strict)
                return
            index = 0
            while index + 1 < len(names):
                yield names, f"{base_location}/Names[{index}]", index
                index += 2
            if len(names) % 2 == 1:
                cls._report_malformed(
                    "Embedded files name list has an odd number of elements; "
                    f"ignoring trailing entry: {names[-1]}",
                    strict=strict,
                )

    @classmethod
    def _load_from_names(cls, names: ArrayObject, strict: bool = False) -> Iterator[EmbeddedFile]:
        """
        Convert the given flat name tree array into class instances.

        Args:
            names: The name tree to load the data from.
            strict: Whether to raise an exception on a file specification that is not a dictionary
                instead of issuing a warning and skipping it.

        Returns:
            Iterable of class instances for the files found.
        """
        # This is a name tree of the format [name_1, reference_1, name_2, reference_2, ...]
        for i, name in enumerate(names):
            if isinstance(name, (str, bytes)):
                # Keys are handled together with their value at the next position.
                continue
            file_dictionary = name.get_object()
            if isinstance(file_dictionary, NullObject):
                # A null value is equivalent to an omitted entry.
                continue
            if not isinstance(file_dictionary, DictionaryObject):
                cls._report_malformed(
                    f"Embedded file specification is not a dictionary: {file_dictionary}", strict=strict
                )
                continue
            direct_name = names[i - 1].get_object() if i > 0 else None
            primary_name = str(direct_name) if isinstance(direct_name, (str, bytes)) else ""
            yield EmbeddedFile(
                name=primary_name,
                pdf_object=file_dictionary,
                parent=names,
                sources=[
                    AttachmentSource(
                        kind=AttachmentSource.NAME_TREE,
                        location=f"/Names/EmbeddedFiles/Names[{i - 1}]",
                        name=primary_name or None,
                    )
                ],
            )

    @staticmethod
    def _name_from_specification(
        file_specification: DictionaryObject, fallback: object | None = None
    ) -> str:
        """Return the best available display name of a file specification dictionary."""
        for key in (FileSpecificationDictionaryEntries.UF, FileSpecificationDictionaryEntries.F):
            if key in file_specification:
                value = file_specification[key].get_object()
                if isinstance(value, (str, bytes)):
                    return str(value)
        if isinstance(fallback, (str, bytes)):
            return str(fallback)
        return ""

    @classmethod
    def _load_name_tree_attachments(
        cls, catalog: DictionaryObject, strict: bool
    ) -> Iterator[tuple[DictionaryObject, AttachmentSource, str, ArrayObject | None]]:
        """
        Yield ``(file_specification, source, name, parent_array)`` for every
        entry of the catalog's embedded files name tree.
        """
        if CA.NAMES not in catalog:
            return
        names_root = catalog[CA.NAMES].get_object()
        if isinstance(names_root, NullObject):
            # A null value is equivalent to an omitted entry.
            return
        if not isinstance(names_root, DictionaryObject):
            cls._report_malformed(f"Names tree is not a dictionary: {names_root}", strict=strict)
            return
        if "/EmbeddedFiles" not in names_root:
            return
        container = names_root["/EmbeddedFiles"].get_object()
        if isinstance(container, NullObject):
            return
        if not isinstance(container, DictionaryObject):
            cls._report_malformed(
                f"Embedded files entry is not a dictionary: {container}", strict=strict
            )
            return

        for names_array, location, key_index in cls._iter_name_tree(
            container, base_location="/Names/EmbeddedFiles", strict=strict
        ):
            value = cast(PdfObject, names_array[key_index + 1]).get_object()
            if isinstance(value, NullObject):
                # A null value is equivalent to an omitted entry.
                continue
            if not isinstance(value, DictionaryObject):
                cls._report_malformed(
                    f"Embedded file specification is not a dictionary: {value}", strict=strict
                )
                continue
            key = names_array[key_index].get_object()
            # The name tree key remains the primary name, independently of the
            # /F and /UF entries of the file specification dictionary.
            primary_name = str(key) if isinstance(key, (str, bytes)) else ""
            source = AttachmentSource(
                kind=AttachmentSource.NAME_TREE, location=location, name=primary_name or None
            )
            yield value, source, primary_name, names_array

    @classmethod
    def _iter_associated_files(
        cls,
        document: PdfDocCommon,
        strict: bool,
    ) -> Iterator[tuple[DictionaryObject, AttachmentSource]]:
        """
        Yield ``(file_specification, source)`` for the associated files (``/AF``)
        referenced by the catalog, the pages and their annotations.

        These references are not part of the embedded files name tree and would
        otherwise be invisible to attachment enumeration. File attachment
        annotations expose their embedded file through ``/FS`` rather than
        ``/AF`` and are covered as well.
        """
        catalog = document.root_object
        yield from cls._iter_associated_files_array(
            catalog[CA.AF].get_object() if CA.AF in catalog else None,
            location="/AF",
            strict=strict,
        )

        page_number = 0
        # Walk the page tree explicitly instead of using document.pages so that
        # a damaged page tree cannot take attachment enumeration down with it.
        pages_root = catalog.get(CA.PAGES)
        if is_null_or_none(pages_root):
            return
        stack: list[PdfObject] = [cast(PdfObject, pages_root)]
        visited: set[int] = set()
        while stack:
            node = stack.pop().get_object()
            if is_null_or_none(node):
                continue
            if not isinstance(node, DictionaryObject):
                cls._report_malformed(f"Page tree node is not a dictionary: {node}", strict=strict)
                continue
            node_id = id(node)
            if node_id in visited:
                cls._report_malformed("Detected a cycle in the page tree.", strict=strict)
                continue
            visited.add(node_id)

            if "/Kids" in node:
                kids = node["/Kids"].get_object()
                if isinstance(kids, ArrayObject):
                    # Reverse to preserve the document order when popping the stack.
                    stack.extend(reversed(list(kids)))
                elif not isinstance(kids, NullObject):
                    cls._report_malformed(f"Page tree /Kids is not an array: {kids}", strict=strict)
                continue

            page_location = f"/Pages[{page_number}]"
            page_number += 1
            yield from cls._iter_associated_files_array(
                node[CA.AF].get_object() if CA.AF in node else None,
                location=f"{page_location}/AF",
                strict=strict,
            )

            annotations = node.get(PG.ANNOTS)
            if is_null_or_none(annotations):
                continue
            annotations = annotations.get_object()
            if not isinstance(annotations, ArrayObject):
                cls._report_malformed(
                    f"Page annotations are not an array: {annotations}", strict=strict
                )
                continue
            for annotation_index, annotation in enumerate(annotations):
                annotation_object = annotation.get_object()
                if not isinstance(annotation_object, DictionaryObject):
                    cls._report_malformed(
                        f"Annotation is not a dictionary: {annotation_object}", strict=strict
                    )
                    continue
                annotation_location = f"{page_location}/Annots[{annotation_index}]"
                # File attachment annotations reference their file through /FS.
                file_specification = annotation_object.get(
                    FileSpecificationDictionaryEntries.FS
                )
                if not is_null_or_none(file_specification):
                    yield from cls._iter_file_specification(
                        cast(PdfObject, file_specification),
                        location=f"{annotation_location}/FS",
                        strict=strict,
                    )
                # Other annotations may carry associated files through /AF.
                if CA.AF in annotation_object:
                    yield from cls._iter_associated_files_array(
                        annotation_object[CA.AF].get_object(),
                        location=f"{annotation_location}/AF",
                        strict=strict,
                    )

    @classmethod
    def _iter_associated_files_array(
        cls, array: PdfObject | None, *, location: str, strict: bool
    ) -> Iterator[tuple[DictionaryObject, AttachmentSource]]:
        """Yield the file specifications stored in an ``/AF`` array."""
        if array is None or isinstance(array, NullObject):
            return
        resolved_array = array.get_object()
        if not isinstance(resolved_array, ArrayObject):
            cls._report_malformed(
                f"Associated files entry is not an array: {resolved_array}", strict=strict
            )
            return
        for index, entry in enumerate(resolved_array):
            entry_location = f"{location}[{index}]"
            yield from cls._iter_file_specification(entry, location=entry_location, strict=strict)

    @classmethod
    def _iter_file_specification(
        cls, entry: PdfObject, *, location: str, strict: bool
    ) -> Iterator[tuple[DictionaryObject, AttachmentSource]]:
        """Validate one file specification reference and wrap it in a source."""
        file_specification = entry.get_object()
        if isinstance(file_specification, NullObject):
            # A null value is equivalent to an omitted entry.
            return
        if not isinstance(file_specification, DictionaryObject):
            cls._report_malformed(
                f"Associated file specification is not a dictionary: {file_specification}",
                strict=strict,
            )
            return
        source = AttachmentSource(
            kind=AttachmentSource.ASSOCIATED_FILE,
            location=location,
            name=cls._name_from_specification(file_specification) or None,
        )
        yield file_specification, source

    @classmethod
    def _load_all(
        cls, document: PdfDocCommon, strict: bool = False
    ) -> Iterator[EmbeddedFile]:
        """
        Enumerate every embedded file reachable from the document.

        Files registered in the embedded files name tree are collected first,
        followed by the associated files (``/AF``) of the catalog, the pages and
        their annotations (including file attachment annotations). The same
        file specification object, even when referenced from several places or
        under several names, is reported exactly once; all of its references are
        preserved in :attr:`EmbeddedFile.sources`.

        Args:
            document: The reader or writer to enumerate.
            strict: Whether to raise an exception on malformed structures
                instead of issuing a warning and skipping them.

        Returns:
            Iterable of class instances for the files found.
        """
        catalog = document.root_object
        # Keyed by the resolved file specification object, so that the same
        # object referenced through several indirect references is merged.
        merged: dict[int, EmbeddedFile] = {}
        # Name tree entries keep the name tree key as their primary name.
        for file_specification, source, name, parent in cls._load_name_tree_attachments(
            catalog, strict=strict
        ):
            existing = merged.get(id(file_specification))
            if existing is None:
                merged[id(file_specification)] = EmbeddedFile(
                    name=name,
                    pdf_object=file_specification,
                    parent=parent,
                    sources=[source],
                )
            else:
                existing._sources.append(source)
                if existing._parent is None:
                    existing._parent = parent

        # Associated files and annotation file specifications are merged into
        # the name tree entries when they point at the same object.
        for file_specification, source in cls._iter_associated_files(document, strict=strict):
            existing = merged.get(id(file_specification))
            if existing is None:
                merged[id(file_specification)] = EmbeddedFile(
                    name=cls._name_from_specification(file_specification),
                    pdf_object=file_specification,
                    sources=[source],
                )
            elif source not in existing._sources:
                existing._sources.append(source)

        yield from merged.values()

    @classmethod
    def _load(cls, catalog: DictionaryObject, strict: bool = False) -> Iterator[EmbeddedFile]:
        """
        Load the embedded files registered in the document's embedded files name tree.

        This method and its signature are considered internal API and thus not exposed publicly for now.
        Use :attr:`PdfReader.attachment_list<pypdf.PdfReader.attachment_list>` to enumerate
        every embedded file, including associated files.

        Args:
            catalog: The document catalog to load from.
            strict: Whether to raise an exception on malformed name trees
                instead of issuing a warning and skipping them.

        Returns:
            Iterable of class instances for the files found.
        """
        for file_specification, source, name, parent in cls._load_name_tree_attachments(
            catalog, strict=strict
        ):
            yield EmbeddedFile(
                name=name,
                pdf_object=file_specification,
                parent=parent,
                sources=[source],
            )
