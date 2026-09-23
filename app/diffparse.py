"""Unified-diff parsing and per-file bidi auditing.

A unified diff is parsed into per-file patches; only the **added** lines
(``+`` prefix) inside hunks are fed to the bidi parser. File headers,
removed lines, context lines and the ``\\ No newline at end of file``
marker never become audited content.

For every file with added content the bidi parser runs once over the added
lines (joined in new-file order, across all of the file's hunks). Every
parser hit -- control character, error, dangerous span -- is then mapped
back to:

* the new file path (from the ``+++`` header, ``a/``/``b/`` prefix stripped,
  ``/dev/null`` denotes a deletion),
* the line/column inside the **new file** (hunk new-side counters, advanced
  per the hunk header),
* the 1-based **diff line** where the owning ``+`` line lives,

while the parser's own ``logical_index`` (offset inside the reconstructed
added text) is preserved.

Malformed diffs raise :class:`DiffFormatError` pointing at the first
offending diff line; nothing is persisted by code in this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .bidi import parse_bidi

# ---------------------------------------------------------------------------
# Structural constants
# ---------------------------------------------------------------------------

# ``@@ -old_start[,old_count] +new_start[,new_count] @@[ section]``
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$"
)

# Every error string emitted by bidi.parse_bidi anchors at the control that
# triggers it with "logical index <n> (line l, col c)".
_LOGICAL_INDEX_RE = re.compile(r"logical index (\d+)")

# Git metadata lines that may legally appear between file sections.
_HEADER_PREFIXES = (
    "index ",
    "new file mode ",
    "deleted file mode ",
    "old mode ",
    "new mode ",
    "similarity index ",
    "dissimilarity index ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "Binary files ",
)

_NO_NEWLINE_PREFIX = "\\"


class DiffFormatError(ValueError):
    """The diff text is not a well-formed unified diff.

    ``diff_line`` is the 1-based physical line number of the first detected
    structural error (may be ``len(lines) + 1`` when a hunk is truncated
    right at end of input).
    """

    def __init__(self, message: str, diff_line: int) -> None:
        super().__init__(f"{message} (diff line {diff_line})")
        self.message = message
        self.diff_line = diff_line


@dataclass
class _AddedLine:
    content: str             # line content without the leading '+' / EOL
    file_line: int           # 1-based line number inside the new file
    diff_line: int           # 1-based physical line number in the diff text
    unterminated: bool = False  # a '\ No newline' marker follows this line


@dataclass
class _FilePatch:
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    plus_header: bool = False  # a '+++ ' header was seen (even /dev/null)
    added: list[_AddedLine] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_diff_path(raw: str) -> Optional[str]:
    """Extract a path from a ``---``/``+++`` header value.

    Returns ``None`` for ``/dev/null`` (file absent on that side). Strips an
    optional tab-separated timestamp and the git ``a/``/``b/`` prefix.
    """
    path = raw.split("\t", 1)[0].strip()
    if path == "/dev/null":
        return None
    if len(path) >= 2 and path[0] in ("a", "b") and path[1] == "/":
        path = path[2:]
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        # git C-style quotes for unusual paths
        path = path[1:-1]
    return path or None


def parse_unified_diff(diff_text: str) -> list[_FilePatch]:
    """Parse unified diff text into ordered per-file patches.

    Raises :class:`DiffFormatError` on the first structural problem.
    """
    if not diff_text or not diff_text.strip():
        raise DiffFormatError("diff input is empty", 1)

    physical = diff_text.split("\n")
    # split() leaves one spurious empty element after a trailing newline
    if diff_text.endswith("\n"):
        physical.pop()

    patches: list[_FilePatch] = []
    patch: Optional[_FilePatch] = None

    in_hunk = False
    header_line = 0
    old_count = new_count = 0
    seen_old = seen_new = 0
    old_line = new_line = 0
    previous_was_body = False  # a content line a '\' marker may attach to

    def finish_hunk(error_line: int) -> None:
        """Validate a hunk that ends because a non-body line was reached."""
        nonlocal in_hunk
        if not in_hunk:
            return
        if seen_old < old_count or seen_new < new_count:
            raise DiffFormatError(
                "hunk starting at diff line %d declares %d old/%d new lines "
                "but its body contains %d old/%d new lines" % (
                    header_line, old_count, new_count,
                    seen_old, seen_new,
                ),
                error_line,
            )
        in_hunk = False

    for lineno, raw_line in enumerate(physical, start=1):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line

        # ---- inside a hunk: +, -, space, empty or '\' belong to the body --
        if in_hunk:
            if line.startswith("+") and not line.startswith("+++ "):
                # A body added line literally starting with "+++ " is encoded
                # as "++++ ..."; the bare form always starts the next file.
                if seen_new >= new_count:
                    raise DiffFormatError(
                        "hunk starting at diff line %d has more new-side "
                        "lines than its header declares" % header_line,
                        lineno,
                    )
                patch.added.append(_AddedLine(
                    content=line[1:], file_line=new_line, diff_line=lineno,
                ))
                new_line += 1
                seen_new += 1
                previous_was_body = True
                continue
            if line.startswith("-") and not line.startswith("--- "):
                if seen_old >= old_count:
                    raise DiffFormatError(
                        "hunk starting at diff line %d has more old-side "
                        "lines than its header declares" % header_line,
                        lineno,
                    )
                old_line += 1
                seen_old += 1
                previous_was_body = True
                continue
            if line.startswith(" ") or line == "":
                # Context line; an empty line is the whitespace-stripped
                # form of an empty context line.
                if seen_new >= new_count or seen_old >= old_count:
                    raise DiffFormatError(
                        "hunk starting at diff line %d has more body lines "
                        "than its header declares" % header_line,
                        lineno,
                    )
                old_line += 1
                new_line += 1
                seen_old += 1
                seen_new += 1
                previous_was_body = True
                continue
            if line.startswith(_NO_NEWLINE_PREFIX):
                if not previous_was_body:
                    raise DiffFormatError(
                        "'\\ No newline' marker is not attached to any hunk "
                        "body line", lineno,
                    )
                # The marker consumes no line on either side: suppress the
                # line-number advance already made for the preceding content
                # line, since that line has no terminator and the next bytes
                # continue on the same file line.
                prev_raw = physical[lineno - 2]
                prev = prev_raw[:-1] if prev_raw.endswith("\r") else prev_raw
                if prev.startswith("+") and not prev.startswith("+++ "):
                    new_line -= 1
                    patch.added[-1].unterminated = True
                elif prev.startswith("-") and not prev.startswith("--- "):
                    old_line -= 1
                else:
                    new_line -= 1
                    old_line -= 1
                previous_was_body = False
                continue
            # Any other line closes the hunk, then is handled as a header.
            finish_hunk(lineno)

        # ---------------------------- headers -----------------------------
        if line.startswith("diff --git "):
            patch = _FilePatch()
            patches.append(patch)
            continue

        if line.startswith("@@"):
            match = _HUNK_HEADER_RE.match(line)
            if match is None:
                raise DiffFormatError(
                    "malformed hunk header (expected "
                    "'@@ -start[,count] +start[,count] @@')", lineno,
                )
            if patch is None or not patch.plus_header:
                raise DiffFormatError(
                    "hunk header appears before a '+++ ' file header", lineno,
                )
            old_start, new_start = int(match.group(1)), int(match.group(3))
            old_count = int(match.group(2) or 1)
            new_count = int(match.group(4) or 1)
            seen_old = seen_new = 0
            old_line, new_line = old_start, new_start
            header_line = lineno
            in_hunk = True
            previous_was_body = False
            continue

        if line.startswith("--- "):
            old_path = _parse_diff_path(line[4:])
            if (patch is None or patch.old_path is not None or patch.added
                    or patch.plus_header):
                patch = _FilePatch(old_path=old_path)
                patches.append(patch)
            else:
                patch.old_path = old_path
            continue

        if line.startswith("+++ "):
            new_path = _parse_diff_path(line[4:])
            if (patch is None or patch.plus_header or patch.added):
                patch = _FilePatch(new_path=new_path, plus_header=True)
                patches.append(patch)
            else:
                patch.new_path = new_path
                patch.plus_header = True
            continue

        if line.startswith(_NO_NEWLINE_PREFIX):
            raise DiffFormatError(
                "'\\ No newline' marker appears outside of a hunk", lineno,
            )

        if line.startswith(("+", "-", " ")) or line == "":
            raise DiffFormatError(
                "diff body line appears outside of any hunk", lineno,
            )

        if any(line.startswith(prefix) for prefix in _HEADER_PREFIXES):
            continue

        raise DiffFormatError(
            "unrecognized line outside of any hunk (not a file header, hunk "
            "header or known git metadata line)", lineno,
        )

    if in_hunk:
        finish_hunk(len(physical) + 1)

    return patches


# ---------------------------------------------------------------------------
# Audit + remapping
# ---------------------------------------------------------------------------

def _reconstruct_added_text(added: list[_AddedLine]) -> str:
    """Join added lines exactly as they would appear in the new file.

    Terminated lines are separated by ``\\n``; a line carrying a
    ``\\ No newline`` marker flows directly into the next added line.
    """
    parts: list[str] = []
    for index, entry in enumerate(added):
        parts.append(entry.content)
        if index < len(added) - 1 and not entry.unterminated:
            parts.append("\n")
    return "".join(parts)


class _Mapper:
    """Map logical indices inside reconstructed added text back to a file."""

    def __init__(self, added: list[_AddedLine]) -> None:
        self.added = added
        self.starts: list[int] = []
        offset = 0
        for index, entry in enumerate(added):
            self.starts.append(offset)
            offset += len(entry.content)
            if index < len(added) - 1 and not entry.unterminated:
                offset += 1  # '\n' between two terminated added lines
        self.length = offset
    def locate(self, index: int) -> tuple[int, int, int]:
        """Return ``(new_file_line, column, diff_line)`` for a logical index.

        Accepts indices in ``0..len(text)``; ``len(text)`` (an exclusive
        span end) resolves to the first column past the final character.
        """
        last = len(self.added) - 1
        for k, entry in enumerate(self.added):
            start = self.starts[k]
            end = start + len(entry.content)
            if start <= index < end:
                # a character inside this added line's content
                return entry.file_line, index - start + 1, entry.diff_line
            if index == end:
                if k < last and entry.unterminated:
                    nxt = self.added[k + 1]
                    return nxt.file_line, 1, nxt.diff_line
                # the joining '\n' (column past content) or end of all text
                return entry.file_line, len(entry.content) + 1, entry.diff_line
        entry = self.added[last]
        return entry.file_line, len(entry.content) + 1, entry.diff_line


_RISK_ORDER = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def audit_diff(diff_text: str) -> list[dict]:
    """Parse a unified diff and audit every file's added content.

    Returns one audit plan per file that actually has added lines, in diff
    order. Raises :class:`DiffFormatError` before producing any plan when
    the diff is malformed, so callers persist nothing on invalid input.
    """
    patches = parse_unified_diff(diff_text)

    plans: list[dict] = []
    for patch in patches:
        if not patch.added:
            continue
        path = patch.new_path
        added_text = _reconstruct_added_text(patch.added)
        result = parse_bidi(added_text).to_dict()
        mapper = _Mapper(patch.added)

        controls: list[dict] = []
        for control in result["controls"]:
            file_line, column, diff_line = mapper.locate(
                control["logical_index"]
            )
            mapped = dict(control)
            mapped.update({
                "path": path,
                "file_position": {"line": file_line, "column": column},
                "diff_line": diff_line,
            })
            controls.append(mapped)

        errors: list[dict] = []
        for message in result["errors"]:
            match = _LOGICAL_INDEX_RE.search(message)
            if match is None:  # defensive: every current error carries one
                errors.append({
                    "message": message, "logical_index": None, "path": path,
                    "file_position": None, "diff_line": None,
                })
                continue
            logical_index = int(match.group(1))
            file_line, column, diff_line = mapper.locate(logical_index)
            errors.append({
                "message": message,
                "logical_index": logical_index,
                "path": path,
                "file_position": {"line": file_line, "column": column},
                "diff_line": diff_line,
            })

        spans: list[dict] = []
        for span in result["dangerous_spans"]:
            start_line, start_col, start_diff = mapper.locate(span["start"])
            end_line, end_col, end_diff = mapper.locate(span["end"])
            mapped = dict(span)
            mapped.update({
                "path": path,
                "start_position": {"line": start_line, "column": start_col},
                "end_position": {"line": end_line, "column": end_col},
                "start_diff_line": start_diff,
                "end_diff_line": end_diff,
            })
            spans.append(mapped)

        plans.append({
            "path": path,
            "text": added_text,
            "risk_level": result["risk_level"],
            "added_line_count": len(patch.added),
            "result": result,
            "mapped": {
                "controls": controls,
                "errors": errors,
                "dangerous_spans": spans,
            },
        })

    return plans


def highest_risk(levels: list[str]) -> str:
    """Aggregate per-file risk levels into the overall highest level."""
    highest = "info"
    for level in levels:
        if _RISK_ORDER[level] > _RISK_ORDER[highest]:
            highest = level
    return highest
