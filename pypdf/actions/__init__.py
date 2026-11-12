"""
PDF includes a wide variety of standard action types, whose characteristics and
behaviour are defined by an action dictionary. These are defined in this
submodule.

Trigger events are the other component of actions, and are specific to their
associated object.

The :mod:`pypdf.actions._security` helpers provide optional inspection and
cleanup of those actions for workflows, such as download services, that only
want to keep in-document navigation and explicitly allowed web links.
"""

from ._actions import Action, JavaScript, PageTrigger
from ._security import (
    ActionFinding,
    ActionLocation,
    ActionPolicy,
    ActionScanner,
    LocationKind,
    sanitize_actions,
)

__all__ = [
    "Action",
    "ActionFinding",
    "ActionLocation",
    "ActionPolicy",
    "ActionScanner",
    "JavaScript",
    "LocationKind",
    "PageTrigger",
    "sanitize_actions",
]
