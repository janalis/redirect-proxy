#!/usr/bin/env python3
"""Check that failed chmod never writes private content or changes originals."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def erlang(code, deny_mode=False, umask=-1, deny_path=None, deny_create_path=None):
    ebins = sorted(str(path) for path in Path("build/dev/erlang").glob("*/ebin"))
    command = ["erl", "-noshell", "-pa", *ebins,
               "-eval", code + ", halt()."]
    if deny_mode or deny_path is not None or deny_create_path is not None:
        policy = "(version 1)(allow default)"
        if deny_mode:
            policy += "(deny file-write-mode)"
        if deny_path is not None:
            policy += "(deny file-write* (literal " + json.dumps(str(deny_path.resolve())) + "))"
        if deny_create_path is not None:
            policy += "(deny file-write-create (literal " + json.dumps(str(deny_create_path.resolve())) + "))"
        command = ["/usr/bin/sandbox-exec", "-p", policy] + command
    subprocess.run(command, check=True, timeout=30, umask=umask)


def binary(path):
    return "list_to_binary(" + json.dumps(str(path)) + ")"


def mode(path):
    return path.stat().st_mode & 0o777


def main():
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists():
        print("SKIP permission-denial regression: requires macOS sandbox-exec")
        return
    directory = Path(tempfile.mkdtemp(prefix="rp-permissions-"))
    try:
        private = directory / "private"
        ordinary = directory / "ordinary"
        source = directory / "source"
        backup = directory / "backup"
        for path in (private, ordinary, source):
            path.write_text("original")
            path.chmod(0o640)
        source.chmod(0o600)
        absent = directory / "absent"
        # Verify actual OS denial, then check that each API propagates it.
        code = (
            f'{{error, eperm}} = file:change_mode({binary(source)}, 8#600), '
            f'{{error, <<"eperm">>}} = redirect_proxy_file_ffi:atomic_write_private({binary(absent)}, <<"secret">>), '
            f'{{error, <<"eperm">>}} = redirect_proxy_file_ffi:atomic_write_private({binary(private)}, <<"secret">>), '
            f'{{error, <<"eperm">>}} = redirect_proxy_file_ffi:atomic_write({binary(ordinary)}, <<"changed">>), '
            f'{{error, <<"eperm">>}} = redirect_proxy_file_ffi:copy_file_as({binary(source)}, {binary(backup)})'
        )
        erlang(code, deny_mode=True)
        assert not absent.exists() and not backup.exists()
        assert sorted(p.name for p in directory.iterdir()) == ["ordinary", "private", "source"]
        for path in (private, ordinary, source):
            assert path.read_text() == "original"
        assert mode(private) == mode(ordinary) == 0o640
        assert mode(source) == 0o600
        # Normal operation still preserves permissions and copies content.
        erlang(
            f'{{ok, nil}} = redirect_proxy_file_ffi:atomic_write_private({binary(absent)}, <<"secret">>), '
            f'{{ok, nil}} = redirect_proxy_file_ffi:atomic_write_private({binary(private)}, <<"secret">>), '
            f'{{ok, nil}} = redirect_proxy_file_ffi:atomic_write({binary(ordinary)}, <<"changed">>), '
            f'{{ok, nil}} = redirect_proxy_file_ffi:copy_file_as({binary(source)}, {binary(backup)})'
        )
        assert absent.read_text() == private.read_text() == "secret"
        assert ordinary.read_text() == "changed" and backup.read_text() == "original"
        assert mode(absent) == mode(backup) == 0o600
        assert mode(private) == mode(ordinary) == 0o640
        # A first-ever active log has no inherited mode: honor the umask.
        first = directory / "first.log"
        erlang(
            f'{{ok, W}} = redirect_proxy_access_writer:start({binary(first)}, 0, 1, false), '
            'ok = redirect_proxy_access_writer:stop(W)',
            umask=0o027,
        )
        assert mode(first) == 0o640
        # Compression must preserve the raw archive and the old gzip file
        # when setting the new archive's permissions is denied.
        access = directory / "access.log"
        access.write_text("")
        access.chmod(0o600)
        compressed = directory / "access.log.0.gz"
        compressed.write_text("previous archive")
        erlang(
            f'{{ok, W}} = redirect_proxy_access_writer:start({binary(access)}, 65536, 1, true), '
            'ok = redirect_proxy_access_writer:send(W, binary:copy(<<"x">>, 70000)), '
            'ok = redirect_proxy_access_writer:sync(W), '
            # Force multiple ordinary retry checks. A lost remembered mode
            # would recreate the active file under the umask and leak bytes.
            'lists:foreach(fun(_) -> element(1, W) ! check, '
            'ok = redirect_proxy_access_writer:sync(W), '
            'ok = redirect_proxy_access_writer:send(W, <<"must not leak">>), '
            'ok = redirect_proxy_access_writer:sync(W) end, lists:seq(1, 3)), '
            'ok = redirect_proxy_access_writer:stop(W)',
            deny_mode=True,
        )
        raw = directory / "access.log.0"
        assert raw.read_bytes() == b"x" * 70000 + b"\n"
        assert mode(raw) == 0o600
        assert compressed.read_text() == "previous archive"
        assert not access.exists(), "failed active-log recreation leaked a file"
        assert not any(".tmp." in p.name for p in directory.iterdir())
        race = directory / "fallback-race"
        race.mkdir()
        (race / "access.log").write_text("")
        (race / "access.log").chmod(0o600)
        (race / "access.log.replacement").write_text("")
        (race / "access.log.replacement").chmod(0o640)
        erlang(
            f'nil = test_access_writer_ffi:denied_reopen_race({binary(race)})',
            deny_mode=True,
            umask=0o022,
        )
        assert (race / "access.log").read_bytes() == b""
        # Audit rotation prepares the replacement before changing archives
        # and keeps the original active file if permissions cannot be set.
        for kept in (0, 2):
            audit_dir = directory / f"audit-{kept}"
            audit_dir.mkdir()
            audit_path = audit_dir / "audit.jsonl"
            original = b"original audit record\n" * 4000
            audit_path.write_bytes(original)
            audit_path.chmod(0o600)
            previous = audit_dir / "audit.jsonl.1"
            previous.write_text("previous archive")
            erlang(
                f'redirect_proxy@audit:configure(65536, {kept}), '
                f'nil = redirect_proxy@audit:record({binary(audit_path)}, '
                '<<"actor">>, <<"test">>, <<"new">>, none, none)',
                deny_mode=True,
                umask=0o022,
            )
            assert audit_path.read_bytes() == original
            assert mode(audit_path) == 0o600
            assert previous.read_text() == "previous archive"
            assert sorted(p.name for p in audit_dir.iterdir()) == ["audit.jsonl", "audit.jsonl.1"]
        # Publication alone fails after preparation and archive installation.
        # Multiple retries must restore the complete original archive chain.
        rollback_dir = directory / "audit-rollback"
        rollback_dir.mkdir()
        active = rollback_dir / "audit.jsonl"
        active.write_bytes(b"A" * 70000)
        active.chmod(0o600)
        older = rollback_dir / "audit.jsonl.1"
        oldest = rollback_dir / "audit.jsonl.2"
        older.write_bytes(b"B")
        older.chmod(0o600)
        oldest.write_bytes(b"C")
        oldest.chmod(0o640)
        erlang(
            'lists:foreach(fun(_) -> '
            f'{{error, _}} = redirect_proxy_file_ffi:audit_rotate({binary(active)}, '
            '<<"new entry">>, 8#600, 2) end, lists:seq(1, 3))',
            deny_path=active,
            umask=0o022,
        )
        assert active.read_bytes() == b"A" * 70000
        assert older.read_bytes() == b"B" and mode(older) == 0o600
        assert oldest.read_bytes() == b"C" and mode(oldest) == 0o640
        assert sorted(p.name for p in rollback_dir.iterdir()) == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]
        # If the OS denies restoring an original archive too, retain its
        # staged inode and return a diagnostic naming the recovery directory.
        recovery_dir = directory / "audit-recovery"
        recovery_dir.mkdir()
        current = recovery_dir / "audit.jsonl"
        current.write_bytes(b"A" * 70000)
        first_archive = recovery_dir / "audit.jsonl.1"
        first_archive.write_bytes(b"B")
        first_archive.chmod(0o600)
        second_archive = recovery_dir / "audit.jsonl.2"
        second_archive.write_bytes(b"C")
        erlang(
            f'{{error, Message}} = redirect_proxy_file_ffi:audit_rotate({binary(current)}, '
            '<<"new entry">>, 8#600, 2), '
            '{_, _} = binary:match(Message, <<"rollback_failed">>), '
            '{_, _} = binary:match(Message, <<"recover_archives_from">>)',
            deny_create_path=first_archive,
        )
        assert current.read_bytes() == b"A" * 70000
        assert second_archive.read_bytes() == b"C"
        staged = list(recovery_dir.glob("audit.jsonl.rotate.*"))
        assert len(staged) == 1 and staged[0].is_dir()
        assert (staged[0] / "1").read_bytes() == b"B"
        assert mode(staged[0] / "1") == 0o600
        assert mode(staged[0]) == 0o700
        print("permission-denial regression passed")
    finally:
        shutil.rmtree(directory)


if __name__ == "__main__":
    main()
