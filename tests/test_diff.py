"""Tests for POST /api/v1/audits/diff (unified-diff added-lines audit).

Covers:
* multi-file / multi-hunk parsing and reconstruction of added lines only;
* mapping of controls, errors and dangerous spans to new-file path,
  line/column and owning diff line while logical_index is preserved;
* hunk new-side line counters including '\\ No newline at end of file';
* 422 on malformed structure or hunk/header count mismatch, pointing at
  the first bad diff line, with no records written;
* one stored record per file that has added content and highest-risk rollup.
"""

RLO = "‮"
PDF = "‬"
LRI = "⁦"
PDI = "⁩"
LRM = "‎"

DIFF_PATH = "/api/v1/audits/diff"


def _diff(client, text):
    return client.post(DIFF_PATH, json={"diff": text})


# ---------------------------------------------------------------------------
# Basic success path
# ---------------------------------------------------------------------------

def test_diff_ignores_headers_removed_and_context(client):
    diff = (
        "diff --git a/safe.txt b/safe.txt\n"
        "index 1111111..2222222 100644\n"
        "--- a/safe.txt\n"
        "+++ b/safe.txt\n"
        "@@ -1,3 +1,3 @@\n"
        " context one\n"
        f"-removed line with {RLO} here\n"
        "+clean replacement line\n"
        " context three\n"
    )
    resp = _diff(client, diff)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["stored"] is True
    assert body["file_count"] == 1
    assert body["risk_level"] == "info"
    entry = body["files"][0]
    # the removed-line RLO must not leak into the audit
    assert entry["risk_level"] == "info"
    assert entry["controls"] == []
    assert entry["errors"] == []
    assert entry["dangerous_spans"] == []
    # the stored raw text is the added line, not the whole diff
    stored = client.get(f"/api/v1/audits/{entry['id']}").json()
    assert stored["raw_text"] == "clean replacement line"
    assert stored["filename"] == "safe.txt"


def test_diff_multi_file_one_record_per_file_with_additions(client):
    diff = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n"
        "+++ b/a.txt\n"
        "@@ -1 +1 @@\n"
        f"-old {RLO}\n"
        "+new\n"
        "diff --git a/b.txt b/b.txt\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/b.txt\n"
        "@@ -0,0 +1,2 @@\n"
        f"+{RLO}evil.exe\n"
        "+second line\n"
        "diff --git a/c.txt b/c.txt\n"
        "deleted file mode 100644\n"
        "--- a/c.txt\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-only removed\n"
    )
    resp = _diff(client, diff)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # deletion-only file and the file whose only control was removed yield
    # no dangerous findings; two files have added content, none for c.txt
    assert body["file_count"] == 2
    assert [f["path"] for f in body["files"]] == ["a.txt", "b.txt"]
    # highest risk across files: b.txt carries an (unclosed) RLO -> critical
    assert body["risk_level"] == "critical"
    ids = [f["id"] for f in body["files"]]
    assert len(set(ids)) == 2
    # c.txt was not persisted
    listing = client.get("/api/v1/audits").json()
    assert listing["total"] == 2


def test_diff_highest_risk_rollup(client):
    diff = (
        "--- a/low.txt\n+++ b/low.txt\n@@ -1 +1 @@\n"
        f"-x\n+{LRM}mark\n"
        "--- a/high.txt\n+++ b/high.txt\n@@ -1 +1 @@\n"
        f"-y\n+{RLO}x{PDF}\n"
    )
    body = _diff(client, diff).json()
    levels = {f["path"]: f["risk_level"] for f in body["files"]}
    assert levels == {"low.txt": "info", "high.txt": "high"}
    assert body["risk_level"] == "high"


# ---------------------------------------------------------------------------
# Mapping back to file coordinates and diff lines
# ---------------------------------------------------------------------------

def test_diff_control_mapping_uses_new_file_line_and_diff_line(client):
    diff = (
        "diff --git a/src/evil.js b/src/evil.js\n"
        "--- a/src/evil.js\n"
        "+++ b/src/evil.js\n"
        "@@ -10,3 +10,4 @@\n"
        " const a = 1;\n"
        "-const old = 2;\n"
        f'+const x = "{RLO}evil.js{PDF}";\n'
        "+const b = 2;\n"
        " // context\n"
    )
    body = _diff(client, diff).json()
    entry = body["files"][0]
    assert entry["path"] == "src/evil.js"

    rlo, pdf = entry["controls"]
    assert rlo["abbreviation"] == "RLO"
    # logical_index is the parser's offset inside reconstructed added text
    assert rlo["logical_index"] == 11
    # parser's own position still refers to the reconstructed added text
    assert rlo["position"] == {"line": 1, "column": 12}
    # mapping back: new-file line 11, same column, owning diff line 7
    assert rlo["file_position"] == {"line": 11, "column": 12}
    assert rlo["diff_line"] == 7
    assert rlo["path"] == "src/evil.js"
    assert rlo["risk"] == "high"

    assert pdf["abbreviation"] == "PDF"
    assert pdf["file_position"] == {"line": 11, "column": 20}
    assert pdf["diff_line"] == 7
    assert body["risk_level"] == "high"

    span = entry["dangerous_spans"][0]
    assert span["start_position"] == {"line": 11, "column": 12}
    assert span["end_position"] == {"line": 11, "column": 20}
    assert span["start_diff_line"] == 7
    assert span["end_diff_line"] == 7


def test_diff_mapping_across_multiple_hunks(client):
    # Hunk 1 starts new-file line 100; hunk 2 continues at line 300.
    diff = (
        "--- a/f\n+++ b/f\n"
        "@@ -100,1 +100,1 @@\n"
        f"-a\n+{RLO}one\n"
        "@@ -300,2 +300,3 @@\n"
        " keep\n"
        f"+{LRM}two\n"
        " tail\n"
    )
    body = _diff(client, diff).json()
    entry = body["files"][0]
    assert entry["added_line_count"] == 2
    first, second = entry["controls"]
    assert first["abbreviation"] == "RLO"
    assert first["file_position"] == {"line": 100, "column": 1}
    assert first["diff_line"] == 5
    assert second["abbreviation"] == "LRM"
    assert second["file_position"] == {"line": 301, "column": 1}
    assert second["diff_line"] == 8
    # reconstructed parser text sees the two added lines as a 2-line doc
    assert first["logical_index"] == 0
    assert second["logical_index"] == 5  # "‮one\n" then LRM
    assert second["position"] == {"line": 2, "column": 1}


def test_diff_unclosed_error_mapping(client):
    # RLO with no PDF inside the added content -> critical + an error
    # whose anchor is mapped to the owning file line / diff line.
    diff = (
        "--- a/x.js\n+++ b/x.js\n"
        "@@ -42 +42 @@\n"
        "-old\n"
        f"+{RLO}end.js\n"
    )
    body = _diff(client, diff).json()
    entry = body["files"][0]
    assert entry["risk_level"] == "critical"
    assert body["risk_level"] == "critical"

    rlo = entry["controls"][0]
    assert rlo["is_orphan"] is True
    assert rlo["file_position"] == {"line": 42, "column": 1}
    assert rlo["diff_line"] == 5

    assert len(entry["errors"]) == 1
    error = entry["errors"][0]
    assert "RLO" in error["message"]
    assert error["logical_index"] == 0
    assert error["path"] == "x.js"
    assert error["file_position"] == {"line": 42, "column": 1}
    assert error["diff_line"] == 5

    span = entry["dangerous_spans"][0]
    assert span["risk"] == "critical"
    assert span["start_position"] == {"line": 42, "column": 1}
    assert span["end_position"] == {"line": 42, "column": 8}


def test_diff_no_newline_marker_suppresses_line_advance(client):
    # Old file ends without newline; the first new added line is on the same
    # file line 1 and unterminated, so the next added content joins it with
    # no line break. The second hunk then sits at line 20.
    diff = (
        "--- a/f\n+++ b/f\n"
        "@@ -1 +1,2 @@\n"
        "-old\n"
        "\\ No newline at end of file\n"
        f"+ab{RLO}c\n"
        "\\ No newline at end of file\n"
        "+def\n"
        "@@ -20 +20,2 @@\n"
        " keep\n"
        "+second hunk\n"
    )
    body = _diff(client, diff).json()
    entry = body["files"][0]
    # reconstructed added text: unterminated "ab‮c" + "def" (same line),
    # then a real newline before the next hunk's addition
    stored = client.get(f"/api/v1/audits/{entry['id']}").json()
    assert stored["raw_text"] == f"ab{RLO}cdef\nsecond hunk"

    rlo = entry["controls"][0]
    assert rlo["logical_index"] == 2
    assert rlo["file_position"] == {"line": 1, "column": 3}
    assert rlo["diff_line"] == 6


def test_diff_only_blank_added_lines_still_audited(client):
    diff = (
        "--- a/f\n+++ b/f\n"
        "@@ -1 +1 @@\n"
        "-x\n+\n"
    )
    resp = _diff(client, diff)
    assert resp.status_code == 201
    body = resp.json()
    assert body["file_count"] == 1
    assert body["files"][0]["added_line_count"] == 1


# ---------------------------------------------------------------------------
# 422: malformed diffs -- first error line, no writes
# ---------------------------------------------------------------------------

def test_diff_422_empty_input(client):
    for payload in ("", "   \n", "\t\n"):
        resp = _diff(client, payload)
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert detail["error"] == "invalid_unified_diff"
        assert detail["diff_line"] == 1


def test_diff_422_garbage_and_missing_field(client):
    resp = _diff(client, "this is not a diff at all\n")
    assert resp.status_code == 422
    assert resp.json()["detail"]["diff_line"] == 1

    resp = client.post(DIFF_PATH, json={})
    assert resp.status_code == 422


def test_diff_422_hunk_before_plus_header(client):
    resp = _diff(client, "@@ -1 +1 @@\n+a\n")
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["diff_line"] == 1
    assert "+++ " in detail["message"]


def test_diff_422_malformed_hunk_header(client):
    diff = "--- a/f\n+++ b/f\n@@ not a hunk @@\n+a\n"
    resp = _diff(client, diff)
    assert resp.status_code == 422
    assert resp.json()["detail"]["diff_line"] == 3


def test_diff_422_hunk_too_many_lines_points_at_first_extra(client):
    # header allows one new line; two '+', the second is the first error
    diff = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n+a\n+b\n"
    resp = _diff(client, diff)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["diff_line"] == 5
    assert "new-side" in detail["message"]


def test_diff_422_hunk_truncated_at_eof(client):
    # header declares two new lines, only one body line exists
    diff = "--- a/f\n+++ b/f\n@@ -1 +1,2 @@\n+a\n"
    resp = _diff(client, diff)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["diff_line"] == 5  # first missing line
    assert "declares" in detail["message"]


def test_diff_422_old_new_count_mismatch(client):
    # declares one old + one new but body is a pure insertion: the missing
    # old side is detected at end of hunk -> first missing line (line 5)
    diff = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n+a\n"
    resp = _diff(client, diff)
    assert resp.status_code == 422
    assert resp.json()["detail"]["diff_line"] == 5


def test_diff_422_stray_body_line(client):
    resp = _diff(client, "--- a/f\n+++ b/f\n+a out of hunk\n")
    assert resp.status_code == 422
    assert resp.json()["detail"]["diff_line"] == 3


def test_diff_422_double_no_newline_marker(client):
    diff = (
        "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+a\n"
        "\\ No newline at end of file\n"
        "\\ No newline at end of file\n"
    )
    resp = _diff(client, diff)
    assert resp.status_code == 422
    # the hunk finishes (counts satisfied) before the dangling second marker
    detail = resp.json()["detail"]
    assert detail["diff_line"] == 7


def test_diff_422_no_newline_outside_hunk(client):
    diff = "\\ No newline at end of file\n"
    resp = _diff(client, diff)
    assert resp.status_code == 422
    assert resp.json()["detail"]["diff_line"] == 1


def test_diff_422_body_line_after_hunk_garbage(client):
    diff = (
        "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+a\n"
        "random garbage not part of any header\n"
    )
    resp = _diff(client, diff)
    assert resp.status_code == 422
    assert resp.json()["detail"]["diff_line"] == 6


def test_diff_422_does_not_write_any_records(client):
    # First file is clean and would persist; the *second* file is malformed.
    # Validation happens for the whole diff before any insert, so zero rows.
    diff = (
        "--- a/ok.txt\n+++ b/ok.txt\n@@ -1 +1 @@\n-old\n+new\n"
        "--- a/bad.txt\n+++ b/bad.txt\n@@ -1 +1 @@\n+only-new-no-old\n"
    )
    assert _diff(client, diff).status_code == 422
    assert client.get("/api/v1/audits").json()["total"] == 0

    # a valid request afterwards still works and stores normally
    ok = (
        "--- a/ok.txt\n+++ b/ok.txt\n@@ -1 +1 @@\n-old\n+new\n"
    )
    resp = _diff(client, ok)
    assert resp.status_code == 201
    assert client.get("/api/v1/audits").json()["total"] == 1


def test_diff_records_are_reusable_by_other_endpoints(client):
    # Records created via /diff behave like ordinary audit records:
    # verify must be consistent and SARIF export must work.
    diff = (
        "--- a/patch.diff\n+++ b/patch.diff\n@@ -1 +1 @@\n"
        f"-x\n+{RLO}end.js\n"
    )
    entry = _diff(client, diff).json()["files"][0]
    audit_id = entry["id"]

    verify = client.get(f"/api/v1/audits/{audit_id}/verify").json()
    assert verify["consistent"] is True
    assert verify["diff_count"] == 0

    sarif = client.get(f"/api/v1/audits/{audit_id}/sarif")
    assert sarif.status_code == 200
    doc = sarif.json()
    assert doc["runs"][0]["results"]
    uri = (doc["runs"][0]["results"][0]["locations"][0]
           ["physicalLocation"]["artifactLocation"]["uri"])
    assert uri == "patch.diff"
