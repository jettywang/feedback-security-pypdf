"""
Optional inspection and cleanup of PDF actions.

A PDF can carry actions in many places: the catalog open action, the
additional-actions (``/AA``) dictionaries of the document, pages, annotations
and form fields, the ``/A`` entry of link annotations and the document level
JavaScript name tree. Some of these actions can execute scripts, launch
programs or open external files and are therefore not suitable for a download
service that only wants to keep in-document navigation and explicitly allowed
web links.

The entry points in this module never execute anything. They only read the
action dictionaries and either report where an action came from or remove the
disallowed entries. Indirect references, ``/Next`` chains (single dictionary or
array) and cyclic action graphs are all handled.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from .._utils import logger_warning
from ..generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    is_null_or_none,
)

if TYPE_CHECKING:
    from .._page import PageObject
    from .._writer import PdfWriter

#: Navigation actions that only move inside the current document.
NAVIGATION_ACTION_TYPES = frozenset(
    {
        "/GoTo",  # Go to a destination in the current document
        "/SetOCGState",  # Change optional content group state, no external effect
    }
)

#: Actions that are dangerous by default because they can execute code or
#: touch resources outside of the document.
DENIED_ACTION_TYPES = frozenset(
    {
        "/JavaScript",
        "/Launch",
        "/ImportData",
        "/SubmitForm",
        "/ResetForm",
        "/Sound",
        "/Movie",
        "/Rendition",
        "/Trans",
        "/GoToR",  # Remote go-to: opens another PDF file
        "/GoToE",  # Embedded go-to: opens an embedded file
        "/RichMediaExecute",
        "/Hide",
    }
)

#: Trigger keys documented for additional-actions (``/AA``) dictionaries:
#: catalog ``/WC /WS /DS /WP /DP /PC`` (table 45), pages ``/O /C`` (table 195)
#: and annotations/fields ``/E /X /D /U /Fo /Bl /PO /PC /PV /PI`` (table 238).
#: The scanner iterates every ``/AA`` entry, so unknown triggers are covered.


@unique
class LocationKind(Enum):
    """Where an action was found."""

    CATALOG_OPEN_ACTION = "catalog /OpenAction"
    CATALOG_AA = "catalog /AA"
    PAGE_AA = "page /AA"
    ANNOTATION_A = "annotation /A"
    ANNOTATION_AA = "annotation /AA"
    FIELD_AA = "form field /AA"
    JAVASCRIPT_NAME_TREE = "/Names /JavaScript name tree"
    NEXT_ACTION = "/Next chain"


@dataclass(frozen=True)
class ActionLocation:
    """
    A single place in the document from which an action is reachable.

    Attributes:
        kind: The structural location holding the action.
        path: Human readable path, e.g. ``page[0] /AA /O``.
        page_index: Index of the owning page, when applicable.
        trigger: The additional-actions trigger key (``/O``, ``/E`` ...).
        container: The dictionary or array directly containing the action.
        key: The dictionary key or array index used inside ``container``.
    """

    kind: LocationKind
    path: str
    container: DictionaryObject | ArrayObject
    key: str | int
    page_index: int | None = None
    trigger: str | None = None


@dataclass(frozen=True)
class ActionFinding:
    """
    An action reached while walking the document's action structures.

    Attributes:
        action: The resolved action dictionary.
        action_type: Its ``/S`` entry (``/Unknown`` when missing or invalid).
        allowed: Whether ``policy`` accepts the action.
        reason: Why the policy allowed or rejected the action.
        locations: Every place from which this exact action object is
            reachable. A single indirect action may be shared by several
            locations.
        indirect_reference: Reference of the action object, when it is indirect.
    """

    action: DictionaryObject
    action_type: str
    allowed: bool
    reason: str
    locations: list[ActionLocation] = field(default_factory=list)
    indirect_reference: IndirectObject | None = None

    @property
    def source_paths(self) -> list[str]:
        """Human readable paths of every location reaching this action."""
        return [location.path for location in self.locations]


class ActionPolicy:
    """
    Policy deciding which actions may be kept.

    By default only in-document navigation (``/GoTo`` and ``/SetOCGState``)
    and ``/URI`` actions using the ``http``/``https`` schemes are allowed.
    Everything else, including JavaScript, launch and embedded/remote file
    actions, is rejected.

    Args:
        allowed_action_types: Extra action ``/S`` names to accept on top of
            the navigation actions.
        allowed_uri_schemes: URI schemes accepted for ``/URI`` actions.
        allowed_uri_hosts: When given, only these hosts (case-insensitive)
            are accepted; any host is accepted otherwise.
    """

    def __init__(
        self,
        allowed_action_types: frozenset[str] | set[str] | tuple[str, ...] = (),
        allowed_uri_schemes: frozenset[str] | set[str] | tuple[str, ...] = (
            "http",
            "https",
        ),
        allowed_uri_hosts: frozenset[str] | set[str] | tuple[str, ...] | None = None,
    ) -> None:
        self.allowed_action_types = frozenset(allowed_action_types) | NAVIGATION_ACTION_TYPES
        self.allowed_uri_schemes = frozenset(
            scheme.lower() for scheme in allowed_uri_schemes
        )
        self.allowed_uri_hosts = (
            frozenset(host.lower() for host in allowed_uri_hosts)
            if allowed_uri_hosts is not None
            else None
        )

    def evaluate(self, action: DictionaryObject) -> tuple[bool, str]:
        """
        Evaluate one action dictionary.

        Returns:
            A ``(allowed, reason)`` tuple. The reason explains the decision and
            is meant to be shown in reports or logs.
        """
        action_type_object = action.get("/S")
        action_type = (
            str(action_type_object)
            if isinstance(action_type_object, NameObject)
            else "/Unknown"
        )

        if action_type == "/URI":
            return self._evaluate_uri(action)
        if action_type in self.allowed_action_types:
            return True, f"allowed navigation action {action_type}"
        if action_type in DENIED_ACTION_TYPES:
            return (
                False,
                f"denied action {action_type} may execute code or open external content",
            )
        if action_type == "/Unknown":
            return False, "denied action without a valid /S entry"
        return False, f"denied action {action_type} is not on the allow list"

    def _evaluate_uri(self, action: DictionaryObject) -> tuple[bool, str]:
        raw_uri = action.get("/URI")
        if is_null_or_none(raw_uri):
            return False, "denied /URI action without a /URI entry"
        uri = str(_resolve(raw_uri))
        parsed = urlsplit(uri)
        scheme = parsed.scheme.lower()
        if scheme not in self.allowed_uri_schemes:
            return (
                False,
                f"denied /URI action: scheme {scheme or '<none>'!r} is not allowed",
            )
        if self.allowed_uri_hosts is None:
            return True, f"allowed web link ({scheme})"
        hostname = parsed.hostname
        if hostname is None or hostname.lower() not in self.allowed_uri_hosts:
            host_repr = hostname if hostname is not None else "<none>"
            return False, f"denied /URI action: host {host_repr!r} is not allowed"
        return True, f"allowed web link ({scheme})"


class ActionScanner:
    """
    Walk every action reachable from a writer.

    The scanner resolves indirect references itself, follows ``/Next`` chains
    (a single action dictionary or an array of action dictionaries) and tracks
    already visited objects so that cyclic action graphs terminate.

    Args:
        writer: The writer whose actions are inspected.
        policy: Policy used to mark findings as allowed or denied. A default
            :class:`ActionPolicy` is created when omitted.
    """

    def __init__(
        self,
        writer: PdfWriter,
        policy: ActionPolicy | None = None,
    ) -> None:
        self.writer = writer
        self.policy = policy or ActionPolicy()
        self.findings: list[ActionFinding] = []
        self._findings_by_object: dict[int, ActionFinding] = {}
        self._walk_visited: set[int] = set()

    def scan(self) -> list[ActionFinding]:
        """
        Collect every reachable action.

        Calling the method again re-runs a full scan and replaces the previous
        :attr:`findings`, which makes it possible to verify a document after
        cleanup by scanning it again.

        Returns:
            The list of :class:`ActionFinding` objects, in discovery order.
        """
        self.findings = []
        self._findings_by_object = {}
        self._walk_visited = set()
        self._scan_catalog()
        for page_index, page in enumerate(self.writer.pages):
            self._scan_page(page, page_index)
        self._scan_form_fields()
        return list(self.findings)

    def denied_findings(self) -> list[ActionFinding]:
        """Return the findings rejected by the policy."""
        return [finding for finding in self.findings if not finding.allowed]

    def allowed_findings(self) -> list[ActionFinding]:
        """Return the findings accepted by the policy."""
        return [finding for finding in self.findings if finding.allowed]

    def _scan_catalog(self) -> None:
        root = self.writer.root_object
        open_action = root.get("/OpenAction")
        if not is_null_or_none(open_action):
            resolved = _resolve(open_action)
            if isinstance(resolved, DictionaryObject):
                # A bare destination array (page + view arguments) is plain
                # navigation and has no action dictionary to inspect.
                self._walk_from(
                    resolved,
                    ActionLocation(
                        kind=LocationKind.CATALOG_OPEN_ACTION,
                        path="catalog /OpenAction",
                        container=root,
                        key="/OpenAction",
                    ),
                )
            elif not isinstance(resolved, ArrayObject):
                self._warn_malformed("catalog /OpenAction", resolved)

        catalog_aa = root.get("/AA")
        if not is_null_or_none(catalog_aa):
            resolved_aa = _resolve(catalog_aa)
            if isinstance(resolved_aa, DictionaryObject):
                self._scan_aa_dictionary(
                    resolved_aa,
                    LocationKind.CATALOG_AA,
                    "catalog /AA",
                )
            else:
                self._warn_malformed("catalog /AA", resolved_aa)

        names = root.get("/Names")
        if not is_null_or_none(names):
            resolved_names = _resolve(names)
            if isinstance(resolved_names, DictionaryObject):
                self._scan_javascript_name_tree(resolved_names)

    def _scan_page(self, page: PageObject, page_index: int) -> None:
        page_aa = page.get("/AA")
        if not is_null_or_none(page_aa):
            resolved_aa = _resolve(page_aa)
            if isinstance(resolved_aa, DictionaryObject):
                self._scan_aa_dictionary(
                    resolved_aa,
                    LocationKind.PAGE_AA,
                    f"page[{page_index}] /AA",
                    page_index=page_index,
                )
            else:
                self._warn_malformed(f"page[{page_index}] /AA", resolved_aa)

        annotations = page.get("/Annots")
        if is_null_or_none(annotations):
            return
        resolved_annotations = _resolve(annotations)
        if not isinstance(resolved_annotations, ArrayObject):
            self._warn_malformed(f"page[{page_index}] /Annots", resolved_annotations)
            return
        for annotation_index, annotation in enumerate(resolved_annotations):
            if is_null_or_none(annotation):
                continue
            resolved_annotation = _resolve(annotation)
            if not isinstance(resolved_annotation, DictionaryObject):
                self._warn_malformed(
                    f"page[{page_index}] /Annots[{annotation_index}]",
                    resolved_annotation,
                )
                continue
            annotation_path = f"page[{page_index}] /Annots[{annotation_index}]"
            link_action = resolved_annotation.get("/A")
            if not is_null_or_none(link_action):
                resolved_action = _resolve(link_action)
                if isinstance(resolved_action, DictionaryObject):
                    self._walk_from(
                        resolved_action,
                        ActionLocation(
                            kind=LocationKind.ANNOTATION_A,
                            path=f"{annotation_path} /A",
                            container=resolved_annotation,
                            key="/A",
                            page_index=page_index,
                        ),
                    )
                else:
                    self._warn_malformed(f"{annotation_path} /A", resolved_action)
            annotation_aa = resolved_annotation.get("/AA")
            if not is_null_or_none(annotation_aa):
                resolved_aa = _resolve(annotation_aa)
                if isinstance(resolved_aa, DictionaryObject):
                    self._scan_aa_dictionary(
                        resolved_aa,
                        LocationKind.ANNOTATION_AA,
                        f"{annotation_path} /AA",
                        page_index=page_index,
                    )
                else:
                    self._warn_malformed(f"{annotation_path} /AA", resolved_aa)

    def _scan_form_fields(self) -> None:
        root = self.writer.root_object
        acro_form = root.get("/AcroForm")
        if is_null_or_none(acro_form):
            return
        resolved_form = _resolve(acro_form)
        if not isinstance(resolved_form, DictionaryObject):
            self._warn_malformed("catalog /AcroForm", resolved_form)
            return
        fields = resolved_form.get("/Fields")
        if is_null_or_none(fields):
            return
        resolved_fields = _resolve(fields)
        if not isinstance(resolved_fields, ArrayObject):
            self._warn_malformed("catalog /AcroForm /Fields", resolved_fields)
            return
        for field_index, field_ref in enumerate(resolved_fields):
            self._scan_field(field_ref, f"/AcroForm /Fields[{field_index}]")

    def _scan_field(self, field_ref: object, path: str) -> None:
        if is_null_or_none(field_ref):
            return
        field = _resolve(field_ref)
        if not isinstance(field, DictionaryObject):
            self._warn_malformed(path, field)
            return
        field_aa = field.get("/AA")
        if not is_null_or_none(field_aa):
            resolved_aa = _resolve(field_aa)
            if isinstance(resolved_aa, DictionaryObject):
                self._scan_aa_dictionary(
                    resolved_aa,
                    LocationKind.FIELD_AA,
                    f"{path} /AA",
                )
            else:
                self._warn_malformed(f"{path} /AA", resolved_aa)
        kids = field.get("/Kids")
        if not is_null_or_none(kids):
            resolved_kids = _resolve(kids)
            if isinstance(resolved_kids, ArrayObject):
                for kid_index, kid in enumerate(resolved_kids):
                    self._scan_field(kid, f"{path} /Kids[{kid_index}]")

    def _scan_aa_dictionary(
        self,
        aa_dictionary: DictionaryObject,
        kind: LocationKind,
        path_prefix: str,
        page_index: int | None = None,
    ) -> None:
        # Every entry is an action trigger; iterating all of them also covers
        # trigger keys that are not part of the documented tuples above.
        for trigger, value in list(aa_dictionary.items()):
            if not isinstance(trigger, NameObject):
                continue
            if is_null_or_none(value):
                continue
            resolved = _resolve(value)
            if not isinstance(resolved, DictionaryObject):
                self._warn_malformed(f"{path_prefix} {str(trigger)}", resolved)
                continue
            self._walk_from(
                resolved,
                ActionLocation(
                    kind=kind,
                    path=f"{path_prefix} {str(trigger)}",
                    container=aa_dictionary,
                    key=str(trigger),
                    page_index=page_index,
                    trigger=str(trigger),
                ),
            )

    def _scan_javascript_name_tree(self, names: DictionaryObject) -> None:
        javascript_tree = names.get("/JavaScript")
        if is_null_or_none(javascript_tree):
            return
        resolved_tree = _resolve(javascript_tree)
        if not isinstance(resolved_tree, DictionaryObject):
            self._warn_malformed("/Names /JavaScript", resolved_tree)
            return
        for node in _iter_name_tree_nodes(resolved_tree, set()):
            pairs = node.get("/Names")
            if is_null_or_none(pairs):
                continue
            resolved_pairs = _resolve(pairs)
            if not isinstance(resolved_pairs, ArrayObject):
                self._warn_malformed("/Names /JavaScript /Names", resolved_pairs)
                continue
            # /Names alternates name string and action object: name0, action0, ...
            for index in range(1, len(resolved_pairs), 2):
                action_ref = resolved_pairs[index]
                if is_null_or_none(action_ref):
                    continue
                action = _resolve(action_ref)
                if not isinstance(action, DictionaryObject):
                    self._warn_malformed(
                        f"/Names /JavaScript /Names[{index}]", action
                    )
                    continue
                self._walk_from(
                    action,
                    ActionLocation(
                        kind=LocationKind.JAVASCRIPT_NAME_TREE,
                        path=f"/Names /JavaScript /Names[{index}]",
                        container=resolved_pairs,
                        key=index,
                    ),
                )

    def _walk_from(
        self,
        action: DictionaryObject,
        location: ActionLocation,
    ) -> None:
        """Walk an action and its whole reachable ``/Next`` graph.

        Two levels of deduplication are used:

        * :attr:`_walk_visited` remembers every action object reached from any
          root location. A shared indirect action is therefore reported once
          with every location referencing it.
        * A per-path ``chain_visited`` set makes the depth-first walk terminate
          when a ``/Next`` chain loops back to one of the actions on that same
          path, while diamond-shaped chains are still fully explored.
        """
        pending: list[tuple[DictionaryObject, ActionLocation, set[int]]] = [
            (action, location, {_object_key(action)})
        ]
        while pending:
            current, current_location, chain_visited = pending.pop()
            object_key = _object_key(current)
            existing = self._findings_by_object.get(object_key)
            if existing is not None:
                # The same indirect action is reachable from several places;
                # keep every distinct location so the report says where it
                # was found. ActionLocation is a frozen dataclass, so equality
                # compares its fields rather than object identity.
                if current_location not in existing.locations:
                    existing.locations.append(current_location)
                continue
            if object_key in self._walk_visited:
                continue
            self._walk_visited.add(object_key)

            allowed, reason = self.policy.evaluate(current)
            finding = ActionFinding(
                action=current,
                action_type=_action_type(current),
                allowed=allowed,
                reason=reason,
                locations=[current_location],
                indirect_reference=current.indirect_reference
                if isinstance(current.indirect_reference, IndirectObject)
                else None,
            )
            self.findings.append(finding)
            self._findings_by_object[object_key] = finding

            for child, child_location in self._iter_next_children(
                current, current_location.path, chain_visited
            ):
                child_path_visited = set(chain_visited)
                child_path_visited.add(_object_key(child))
                pending.append((child, child_location, child_path_visited))

    def _iter_next_children(
        self,
        action: DictionaryObject,
        root_path: str,
        chain_visited: set[int],
    ) -> Iterator[tuple[DictionaryObject, ActionLocation]]:
        next_value = action.get("/Next")
        if is_null_or_none(next_value):
            return
        resolved_next = _resolve(next_value)

        children: list[tuple[Any, DictionaryObject | ArrayObject, str | int]]
        if isinstance(resolved_next, DictionaryObject):
            children = [(resolved_next, action, "/Next")]
        elif isinstance(resolved_next, ArrayObject):
            children = [
                (item, resolved_next, index)
                for index, item in enumerate(resolved_next)
            ]
        else:
            self._warn_malformed(f"{root_path} /Next", resolved_next)
            return

        for child, container, key in children:
            if is_null_or_none(child):
                continue
            child_action = _resolve(child)
            if not isinstance(child_action, DictionaryObject):
                self._warn_malformed(f"{root_path} /Next", child_action)
                continue
            child_object_key = _object_key(child_action)
            if child_object_key in chain_visited:
                logger_warning(
                    "Detected a cycle in the /Next action chain starting at %(path)s; "
                    "the repeated action is not walked again.",
                    source=__name__,
                    path=root_path,
                )
                continue
            yield child_action, ActionLocation(
                kind=LocationKind.NEXT_ACTION,
                path=f"{root_path} /Next",
                container=container,
                key=key,
            )

    @staticmethod
    def _warn_malformed(path: str, obj: object) -> None:
        logger_warning(
            "Skipping malformed action structure at %(path)s: received %(type)s instead of an action dictionary.",
            source=__name__,
            path=path,
            type=type(obj).__name__,
        )


def _action_type(action: DictionaryObject) -> str:
    action_type = action.get("/S")
    return str(action_type) if isinstance(action_type, NameObject) else "/Unknown"


def _resolve(obj: Any) -> Any:
    """Resolve an indirect reference; direct objects are returned unchanged."""
    if isinstance(obj, IndirectObject):
        return cast(Any, obj.get_object())
    return obj


def _object_key(obj: DictionaryObject) -> int:
    """Stable identity for an action, indirect references included."""
    reference = obj.indirect_reference
    if isinstance(reference, IndirectObject):
        return hash(
            ("indirect", reference.idnum, reference.generation, id(reference.pdf))
        )
    return hash(("direct", id(obj)))


def _iter_name_tree_nodes(
    node: DictionaryObject, visited: set[int]
) -> Iterator[DictionaryObject]:
    node_key = id(node)
    if node_key in visited:
        logger_warning(
            "Detected a cycle in the /JavaScript name tree; the repeated node is skipped.",
            source=__name__,
        )
        return
    visited.add(node_key)
    kids = node.get("/Kids")
    if not is_null_or_none(kids):
        resolved_kids = _resolve(kids)
        if isinstance(resolved_kids, ArrayObject):
            for kid in resolved_kids:
                if is_null_or_none(kid):
                    continue
                resolved_kid = _resolve(kid)
                if isinstance(resolved_kid, DictionaryObject):
                    yield from _iter_name_tree_nodes(resolved_kid, visited)
    if "/Names" in node:
        yield node


def sanitize_actions(
    writer: PdfWriter,
    policy: ActionPolicy | None = None,
) -> list[ActionFinding]:
    """
    Remove every action rejected by ``policy``.

    The scan first collects all reachable actions together with the locations
    referencing them, then the disallowed action objects are detached from
    their containers. ``/Next`` chains are pruned as well, including arrays,
    while allowed actions and plain navigation (annotation ``/Dest`` entries,
    catalog destination arrays) are left untouched.

    Args:
        writer: The writer to clean in place.
        policy: Policy deciding which actions to keep. A default
            :class:`ActionPolicy` is created when omitted.

    Returns:
        The findings of the cleanup scan, including the ``reason`` explaining
        why each removed action was rejected and where it was referenced.
    """
    scanner = ActionScanner(writer, policy)
    findings = scanner.scan()

    # Collect the removals per container first. Array indices recorded during
    # the scan are only valid while the array is unchanged, so array entries
    # are popped together in descending index order.
    dict_keys_to_remove: dict[int, tuple[DictionaryObject, set[str]]] = {}
    array_indices_to_remove: dict[int, tuple[ArrayObject, set[int]]] = {}
    name_tree_arrays: set[int] = set()
    for finding in scanner.denied_findings():
        for location in finding.locations:
            container = location.container
            if isinstance(container, ArrayObject):
                _, indices = array_indices_to_remove.setdefault(
                    id(container), (container, set())
                )
                indices.add(cast(int, location.key))
                if location.kind is LocationKind.JAVASCRIPT_NAME_TREE:
                    name_tree_arrays.add(id(container))
            elif isinstance(container, DictionaryObject):
                _, keys = dict_keys_to_remove.setdefault(
                    id(container), (container, set())
                )
                keys.add(str(location.key))

    for container_id, (container, indices) in array_indices_to_remove.items():
        is_name_tree = container_id in name_tree_arrays
        for index in sorted(indices, reverse=True):
            if not 0 <= index < len(container):
                continue
            container.pop(index)
            # A name tree /Names array alternates a name string and the named
            # action, so removing the action also removes its paired name.
            if is_name_tree and index - 1 >= 0:
                container.pop(index - 1)

    for container, keys in dict_keys_to_remove.values():
        for key in keys:
            if key in container:
                del container[NameObject(key)]

    _drop_empty_aa(writer)
    return findings


def _drop_empty_aa(writer: PdfWriter) -> None:
    """Remove additional-actions dictionaries that became empty."""
    root = writer.root_object
    catalog_aa = root.get("/AA")
    if isinstance(catalog_aa, DictionaryObject) and not catalog_aa:
        del root[NameObject("/AA")]

    names = root.get("/Names")
    if not is_null_or_none(names):
        resolved_names = _resolve(names)
        if isinstance(resolved_names, DictionaryObject):
            resolved_tree = _resolve(resolved_names.get("/JavaScript"))
            if isinstance(resolved_tree, DictionaryObject):
                resolved_pairs = _resolve(resolved_tree.get("/Names"))
                if is_null_or_none(resolved_pairs) or (
                    isinstance(resolved_pairs, ArrayObject) and not resolved_pairs
                ):
                    del resolved_names[NameObject("/JavaScript")]
            if not resolved_names:
                del root[NameObject("/Names")]

    for page in writer.pages:
        page_aa = page.get("/AA")
        if isinstance(page_aa, DictionaryObject) and not page_aa:
            del page[NameObject("/AA")]
        annotations = page.get("/Annots")
        if is_null_or_none(annotations):
            continue
        resolved_annotations = _resolve(annotations)
        if not isinstance(resolved_annotations, ArrayObject):
            continue
        for annotation in resolved_annotations:
            if is_null_or_none(annotation):
                continue
            resolved_annotation = _resolve(annotation)
            if isinstance(resolved_annotation, DictionaryObject):
                annotation_aa = resolved_annotation.get("/AA")
                if isinstance(annotation_aa, DictionaryObject) and not annotation_aa:
                    del resolved_annotation[NameObject("/AA")]

    acro_form = root.get("/AcroForm")
    if not is_null_or_none(acro_form):
        resolved_form = _resolve(acro_form)
        if isinstance(resolved_form, DictionaryObject):
            _drop_empty_aa_in_fields(resolved_form.get("/Fields"))


def _drop_empty_aa_in_fields(fields: object) -> None:
    if is_null_or_none(fields):
        return
    resolved_fields = _resolve(fields)
    if not isinstance(resolved_fields, ArrayObject):
        return
    for field_ref in resolved_fields:
        if is_null_or_none(field_ref):
            continue
        field = _resolve(field_ref)
        if not isinstance(field, DictionaryObject):
            continue
        field_aa = field.get("/AA")
        if isinstance(field_aa, DictionaryObject) and not field_aa:
            del field[NameObject("/AA")]
        _drop_empty_aa_in_fields(field.get("/Kids"))
