# SPDX-License-Identifier: AGPL-3.0-only
"""Tamper tests: edit, delete, reorder and truncate are all caught.

The anchors are what make truncation and a key-holder rewrite detectable, and
only back to the last anchor. Both sides of that limit are tested here.
"""

import json
import shutil

import pytest

from conftest import read_lines, signed_line
from lurewall import signing
from lurewall.canonical import canonical_bytes, sha256_hex
from lurewall.cli import main
from lurewall.entry import make_checkpoint
from lurewall.eventlog import EventLog
from lurewall.verify import format_report, verify_log

MARKER = "ATTACKER-TEXT-7f3a"


@pytest.fixture
def anchored(tmp_path, signer, clock, disk):
    """A 30-entry log with anchors saved off to one side at seq 10, 20 and 30."""
    path = tmp_path / "events.log"
    checkpoint = tmp_path / "served" / "checkpoint.json"
    checkpoint.parent.mkdir()
    anchors = tmp_path / "anchors"
    anchors.mkdir()
    log = EventLog(
        path,
        signer,
        checkpoint_path=checkpoint,
        checkpoint_every=10**9,
        checkpoint_interval_ms=10**12,
        clock=clock,
        disk_free=disk,
        fsync=False,
    )
    for index in range(1, 31):
        log.append("probe", f"192.0.2.{index}", {"ua": f"{MARKER} {index}", "path": "/.env"})
        clock.advance(1000)
        if index % 10 == 0:
            log.checkpoint()
            shutil.copy(checkpoint, anchors / f"{index:08d}.json")
    log.close()
    return path, anchors, signer


def rewrite(path, lines):
    path.write_bytes(b"".join(lines))


def check(path, signer, anchors=None):
    return verify_log(path, signer.public_key_hex, [anchors] if anchors else None)


def test_untouched_log_verifies(anchored):
    path, anchors, signer = anchored
    report = check(path, signer, anchors)
    assert report.ok and report.entries == 30
    assert (report.anchors_valid, report.anchors_matched) == (3, 3)
    assert report.last_matched_anchor_seq == 30 and report.truncated_missing == 0
    assert "RESULT: OK" in format_report(report)


# -- edit ---------------------------------------------------------------------


def test_edit_is_caught_at_the_edited_entry(anchored):
    path, anchors, signer = anchored
    lines = read_lines(path)
    lines[14] = lines[14].replace(b"/.env", b"/.git")
    rewrite(path, lines)
    for report in (check(path, signer), check(path, signer, anchors)):
        assert not report.ok and report.entries == 14
        assert (report.bad_entry.line, report.bad_entry.reason) == (15, "bad_signature")
        assert report.bad_entry.offset == sum(len(line) for line in lines[:14])
        assert report.bad_entry.line_sha256 == sha256_hex(lines[14][:-1])


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        (b'"seq":15', b'"seq":16', "bad_signature"),
        (b'"type":"probe"', b'"type":"block"', "bad_signature"),
        (b'"source":"192.0.2.15"', b'"source":"192.0.2.99"', "bad_signature"),
        (b'"detail":{', b'"detail": {', "not_canonical_json"),
        (b'"detail":{', b'"extra":1,"detail":{', "not_canonical_json"),
        (b'"detail":{', b'"detail":{"a":1.5,', "not_canonical_json"),
        (b'"detail":{', b'"detail":{"a":NaN,', "not_canonical_json"),
        (b'"type":"probe"', b'"type":"probe","type":"probe"', "not_canonical_json"),
        (b"\n", b"\r\n", "not_canonical_json"),
        (b"\n", b" \n", "not_canonical_json"),
    ],
)
def test_every_kind_of_edit_is_caught(anchored, old, new, reason):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    assert old in lines[14]
    lines[14] = lines[14].replace(old, new, 1)
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason, report.entries) == (15, reason, 14)


def test_entry_resigned_with_another_key_is_caught(anchored):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    prev = sha256_hex(lines[13][:-1])
    lines[14] = signed_line(signing.EurekaSigner.ephemeral(), 15, prev, type="unblock")
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (15, "bad_signature")


def test_one_entry_rewritten_by_the_key_holder_breaks_the_next_link(anchored):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    prev = sha256_hex(lines[13][:-1])
    lines[14] = signed_line(signer, 15, prev, type="unblock")
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (16, "bad_prev_hash")


def rechain_from(lines, signer, start):
    """What the key holder can do: rewrite history from ``start`` on, fully re-signed."""
    kept = lines[:start]
    prev = sha256_hex(kept[-1][:-1])
    for seq in range(start + 1, len(lines) + 1):
        line = signed_line(signer, seq, prev, type="probe", detail={"rewritten": True}, ts=seq)
        kept.append(line)
        prev = sha256_hex(line[:-1])
    return kept


def test_full_rewrite_by_the_key_holder_is_caught_only_by_an_anchor(anchored):
    path, anchors, signer = anchored
    rewrite(path, rechain_from(read_lines(path), signer, 14))
    # The stated limit: the log alone cannot show this.
    assert check(path, signer).ok
    report = check(path, signer, anchors)
    assert not report.ok and report.last_matched_anchor_seq == 10
    assert [(p.reason, p.seq) for p in report.anchor_problems] == [
        ("anchor_mismatch", 20),
        ("anchor_mismatch", 30),
    ]
    assert "rewritten at or before it" in format_report(report)


def test_rewrite_after_the_last_anchor_is_not_detectable_and_is_reported_as_uncovered(anchored):
    path, anchors, signer = anchored
    (anchors / "00000030.json").unlink()
    rewrite(path, rechain_from(read_lines(path), signer, 24))
    report = check(path, signer, anchors)
    assert report.ok and report.last_matched_anchor_seq == 20
    text = format_report(report)
    assert "entries 21 to 30 come after the last anchor" in text
    assert "without detection" in text


# -- delete, reorder, duplicate, insert ------------------------------------------


@pytest.mark.parametrize("index", [0, 14, 28])
def test_deleted_entry_is_caught_where_it_was(anchored, index):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    del lines[index]
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (index + 1, "bad_seq")
    assert report.entries == index


def test_reordered_entries_are_caught(anchored):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    lines[14], lines[15] = lines[15], lines[14]
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (15, "bad_seq")


def test_duplicated_entry_is_caught(anchored):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    lines.insert(15, lines[14])
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (16, "bad_seq")


@pytest.mark.parametrize(
    ("junk", "reason"),
    [
        (b"\n", "not_canonical_json"),
        (b"not a log line\n", "not_canonical_json"),
        (b"{}\n", "bad_fields"),
        (b"\x00\xff\xfe binary\n", "not_canonical_json"),
        (
            b'{"detail":{},"prev_hash":"x","seq":16,"sig":"x","source":null,"ts":1,"type":"probe"}\n',
            "bad_fields",
        ),
        (b"A" * (1024 * 1024 + 10) + b"\n", "line_too_long"),
        (b"A" * (3 * 1024 * 1024), "line_too_long"),
    ],
)
def test_inserted_junk_is_caught(anchored, junk, reason):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    lines.insert(15, junk)
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason, report.entries) == (16, reason, 15)


def test_spliced_in_entries_from_another_log_are_caught(anchored, tmp_path, clock, disk):
    path, _anchors, signer = anchored
    other = EventLog(tmp_path / "other.log", signer, clock=clock, disk_free=disk, fsync=False)
    for _ in range(30):
        other.append("unblock")
    other.close()
    lines = read_lines(path)
    lines[14] = read_lines(other.path)[14]  # same key, same seq, different history
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (15, "bad_prev_hash")


def test_wrong_field_types_are_caught(anchored):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    prev = sha256_hex(lines[-1][:-1])
    for change in (
        {"seq": "31"},
        {"seq": True},
        {"seq": 0},
        {"ts": -1},
        {"ts": "now"},
        {"type": "Probe"},
        {"type": 5},
        {"source": 5},
        {"source": "x" * 257},
        {"detail": []},
        {"detail": None},
        {"prev_hash": prev.upper()},
        {"prev_hash": prev[:-1]},
        {"sig": "AAAA"},
        {"sig": 5},
    ):
        body = {
            "seq": 31,
            "ts": 1,
            "type": "probe",
            "source": None,
            "detail": {},
            "prev_hash": prev,
        }
        body.update(change)
        if "sig" not in body:
            body["sig"] = signer.sign(body, signing.DOMAIN_EVENT)
        rewrite(path, [*lines, canonical_bytes(body) + b"\n"])
        report = check(path, signer)
        assert (report.bad_entry.line, report.bad_entry.reason) == (31, "bad_fields"), change


def test_a_checkpoint_signature_cannot_stand_in_for_an_entry_signature(anchored):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    body = {
        "seq": 31,
        "ts": 1,
        "type": "probe",
        "source": None,
        "detail": {},
        "prev_hash": sha256_hex(lines[-1][:-1]),
    }
    body["sig"] = signer.sign(dict(body), signing.DOMAIN_CHECKPOINT)
    rewrite(path, [*lines, canonical_bytes(body) + b"\n"])
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (31, "bad_signature")


def test_respelled_signature_is_caught(anchored):
    path, _anchors, signer = anchored
    lines = read_lines(path)
    entry = json.loads(lines[-1])
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    sig = entry["sig"]
    entry["sig"] = sig[:-3] + alphabet[alphabet.index(sig[-3]) ^ 1] + "=="
    lines[-1] = canonical_bytes(entry) + b"\n"
    rewrite(path, lines)
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (30, "bad_fields")


def test_wrong_public_key_fails_at_the_first_entry(anchored):
    path, _anchors, _signer = anchored
    report = verify_log(path, signing.EurekaSigner.ephemeral().public_key_hex)
    assert (report.bad_entry.line, report.bad_entry.reason, report.entries) == (
        1,
        "bad_signature",
        0,
    )


# -- truncate ---------------------------------------------------------------------


def test_truncation_is_reported_back_to_the_last_anchor(anchored):
    path, anchors, signer = anchored
    rewrite(path, read_lines(path)[:25])
    # The stated limit: without anchors, a shortened log looks complete.
    assert check(path, signer).ok
    report = check(path, signer, anchors)
    assert not report.ok and report.entries == 25
    assert report.truncated_missing == 5 and report.last_matched_anchor_seq == 20
    assert [(p.reason, p.seq) for p in report.anchor_problems] == [("log_truncated", 30)]
    text = format_report(report)
    assert "TRUNCATED: the log ends at seq 25" in text
    assert "at least 5 entries are missing" in text
    assert "last anchor that matches the log: seq 20" in text
    assert "RESULT: FAIL" in text


def test_truncation_past_several_anchors(anchored):
    path, anchors, signer = anchored
    rewrite(path, read_lines(path)[:5])
    report = check(path, signer, anchors)
    assert report.truncated_missing == 25 and report.last_matched_anchor_seq is None
    assert [p.seq for p in report.anchor_problems] == [10, 20, 30]
    assert "No entry is covered" in format_report(report)


def test_emptied_log_is_reported_as_truncated(anchored):
    path, anchors, signer = anchored
    path.write_bytes(b"")
    report = check(path, signer, anchors)
    assert not report.ok and report.truncated_missing == 30


def test_truncation_after_the_last_anchor_is_the_documented_gap(anchored):
    path, anchors, signer = anchored
    (anchors / "00000030.json").unlink()
    rewrite(path, read_lines(path)[:25])
    report = check(path, signer, anchors)
    assert report.ok and report.last_matched_anchor_seq == 20
    assert "entries 21 to 25 come after the last anchor" in format_report(report)


def test_truncation_in_the_middle_of_a_line_is_caught(anchored):
    path, _anchors, signer = anchored
    raw = path.read_bytes()
    path.write_bytes(raw[: len(raw) - 40])
    report = check(path, signer)
    assert (report.bad_entry.line, report.bad_entry.reason) == (30, "unterminated_line")
    assert report.entries == 29


def test_anchors_past_a_bad_entry_are_reported_as_unchecked(anchored):
    path, anchors, signer = anchored
    lines = read_lines(path)
    del lines[14]
    rewrite(path, lines)
    report = check(path, signer, anchors)
    assert report.bad_entry.line == 15 and report.anchors_matched == 1
    assert [(p.reason, p.seq) for p in report.anchor_problems] == [
        ("anchor_unchecked", 20),
        ("anchor_unchecked", 30),
    ]
    assert report.truncated_missing == 0


# -- anchors themselves -------------------------------------------------------------


def test_anchor_not_signed_by_the_key_fails_verification(anchored):
    path, anchors, signer = anchored
    forged = make_checkpoint(signing.EurekaSigner.ephemeral(), 25, "a" * 64, 5)
    (anchors / "forged.json").write_text(json.dumps(forged))
    report = check(path, signer, anchors)
    assert not report.ok and report.anchors_matched == 3
    assert [p.reason for p in report.anchor_problems] == ["anchor_bad_signature"]


def test_edited_anchor_fails_verification(anchored):
    path, anchors, signer = anchored
    file = anchors / "00000020.json"
    checkpoint = json.loads(file.read_text())
    checkpoint["seq"] = 19
    file.write_text(json.dumps(checkpoint))
    report = check(path, signer, anchors)
    assert [p.reason for p in report.anchor_problems] == ["anchor_bad_signature"]


def test_conflicting_signed_anchors_fail_verification(anchored):
    path, anchors, signer = anchored
    (anchors / "conflict.json").write_text(json.dumps(make_checkpoint(signer, 20, "b" * 64, 5)))
    report = check(path, signer, anchors)
    assert not report.ok
    assert ("anchor_conflict", 20) in [(p.reason, p.seq) for p in report.anchor_problems]


def test_an_event_signature_cannot_stand_in_for_a_checkpoint(anchored):
    path, anchors, signer = anchored
    body = {"seq": 30, "head_hash": "c" * 64, "ts": 5}
    fake = {**body, "sig": signer.sign(body, signing.DOMAIN_EVENT)}
    (anchors / "fake.json").write_text(json.dumps(fake))
    report = check(path, signer, anchors)
    assert [p.reason for p in report.anchor_problems] == ["anchor_bad_signature"]


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (b"not json at all", "anchor_not_json"),
        (b"{}", "anchor_bad_fields"),
        (b"[1, 2]", "anchor_bad_fields"),
        (b'{"seq":1.5,"head_hash":"x","ts":1,"sig":"x"}', "anchor_bad_fields"),
        (b'{"seq":1,"head_hash":"x","ts":1,"sig":"x","ip":"192.0.2.1"}', "anchor_bad_fields"),
        (b"[" * 100_000, "anchor_not_json"),
        (b"x" * (1024 * 1024 + 1), "anchor_file_too_large"),
    ],
)
def test_malformed_anchor_files_fail_verification(anchored, content, reason):
    path, anchors, signer = anchored
    (anchors / "junk.json").write_bytes(content)
    report = check(path, signer, anchors)
    assert not report.ok and reason in [p.reason for p in report.anchor_problems]


def test_missing_anchor_path_fails_verification(anchored, tmp_path):
    path, _anchors, signer = anchored
    report = check(path, signer, tmp_path / "nowhere")
    assert [p.reason for p in report.anchor_problems] == ["anchor_path_missing"]


def test_anchor_inputs_as_a_file_a_list_json_lines_and_a_repo_clone(anchored, tmp_path):
    path, anchors, signer = anchored
    checkpoints = [json.loads(file.read_text()) for file in sorted(anchors.iterdir())]

    as_list = tmp_path / "list.json"
    as_list.write_text(json.dumps(checkpoints, indent=2))
    as_lines = tmp_path / "lines.jsonl"
    as_lines.write_text("".join(json.dumps(item) + "\n\n" for item in checkpoints))
    clone = tmp_path / "clone"
    (clone / "2026" / "11").mkdir(parents=True)
    (clone / ".git").mkdir()
    (clone / ".git" / "packed.json").write_text("not an anchor")
    (clone / "README.md").write_text("ignored")
    (clone / "2026" / "11" / "a.json").write_text(json.dumps(checkpoints[0]))
    (clone / "2026" / "11" / "b.json").write_text(json.dumps(checkpoints[2]))

    for source, matched in (
        (as_list, 3),
        (as_lines, 3),
        (clone, 2),
        (anchors / "00000010.json", 1),
    ):
        report = verify_log(path, signer.public_key_hex, [source])
        assert report.ok and report.anchors_matched == matched, source
    report = verify_log(path, signer.public_key_hex, [as_list, as_lines, clone])
    assert report.ok and report.anchors_valid == 3


# -- command line --------------------------------------------------------------------


def run(capsys, *argv):
    code = main([str(arg) for arg in argv])
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_passes_a_good_log(anchored, capsys):
    path, anchors, signer = anchored
    code, out, _err = run(
        capsys, "verify", "--log", path, "--pubkey", signer.public_key_hex, "--anchors", anchors
    )
    assert code == 0 and "RESULT: OK" in out and "30 entries verified" in out


def test_cli_warns_when_no_anchors_are_given(anchored, capsys):
    path, _anchors, signer = anchored
    code, out, _err = run(capsys, "verify", "--log", path, "--pubkey", signer.public_key_hex)
    assert code == 0 and "anchors: none given" in out and "cannot be detected" in out


def test_cli_prints_the_first_bad_entry_and_never_log_content(anchored, capsys):
    path, anchors, signer = anchored
    lines = read_lines(path)
    lines[14] = lines[14].replace(b"/.env", b"/\\u001b[2J" + MARKER.encode())
    rewrite(path, lines)
    for extra in ((), ("--json",)):
        code, out, err = run(
            capsys, "verify", "--log", path, "--pubkey", signer.public_key_hex,
            "--anchors", anchors, *extra,
        )  # fmt: skip
        assert code == 1
        assert MARKER not in out + err and "\x1b" not in out + err and "192.0.2." not in out
    code, out, _err = run(capsys, "verify", "--log", path, "--pubkey", signer.public_key_hex)
    assert "FIRST BAD ENTRY: line 15" in out and "expected seq 15: bad_signature" in out
    assert "RESULT: FAIL" in out


def test_cli_json_report(anchored, capsys):
    path, anchors, signer = anchored
    rewrite(path, read_lines(path)[:25])
    code, out, _err = run(
        capsys, "verify", "--log", path, "--pubkey", signer.public_key_hex,
        "--anchors", anchors, "--json",
    )  # fmt: skip
    report = json.loads(out)
    assert code == 1 and report["ok"] is False
    assert report["entries"] == 25 and report["truncated_missing"] == 5
    assert report["last_matched_anchor_seq"] == 20


def test_cli_reads_the_public_key_from_a_file(anchored, capsys, tmp_path):
    path, _anchors, signer = anchored
    key_file = tmp_path / "lurewall.pub"
    key_file.write_text(signer.public_key_hex.upper() + "\n")
    code, _out, _err = run(capsys, "verify", "--log", path, "--pubkey", key_file)
    assert code == 0


@pytest.mark.parametrize("bad_key", ["", "abc", "zz" * 32, "/no/such/file"])
def test_cli_usage_errors_are_exit_2_not_a_verdict(anchored, capsys, bad_key):
    path, _anchors, _signer = anchored
    code, out, err = run(capsys, "verify", "--log", path, "--pubkey", bad_key)
    assert code == 2 and "RESULT" not in out and "public key" in err


def test_cli_missing_log_is_exit_2(anchored, capsys, tmp_path):
    _path, _anchors, signer = anchored
    code, out, err = run(
        capsys, "verify", "--log", tmp_path / "absent.log", "--pubkey", signer.public_key_hex
    )
    assert code == 2 and "RESULT" not in out and "cannot read the log" in err


def test_keygen_writes_a_private_file_and_never_overwrites(capsys, tmp_path, clock, disk):
    key = tmp_path / "keys" / "lurewall.key"
    code, out, _err = run(capsys, "keygen", "--key", key)
    public = out.strip()
    assert code == 0 and len(public) == 64
    assert key.stat().st_mode & 0o777 == 0o600
    assert json.loads(key.read_text())["private_key_hex"] not in out

    code, out, err = run(capsys, "keygen", "--key", key)
    assert code == 2 and out == "" and "refusing to overwrite" in err

    code, out, _err = run(capsys, "pubkey", "--key", key)
    assert (code, out.strip()) == (0, public)

    signer = signing.EurekaSigner.load(key)
    log = EventLog(tmp_path / "events.log", signer, clock=clock, disk_free=disk)
    log.append("probe")
    log.close()
    assert verify_log(log.path, public).ok


def test_a_key_file_others_can_read_is_refused(capsys, tmp_path):
    key = tmp_path / "lurewall.key"
    run(capsys, "keygen", "--key", key)
    key.chmod(0o644)
    code, out, err = run(capsys, "pubkey", "--key", key)
    assert code == 2 and out == "" and "expected 0600" in err


def test_pubkey_of_a_missing_key_does_not_create_one(capsys, tmp_path):
    key = tmp_path / "typo.key"
    code, _out, err = run(capsys, "pubkey", "--key", key)
    assert code == 2 and "no identity file" in err and not key.exists()
