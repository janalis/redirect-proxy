#!/usr/bin/env python3
"""Check that failed chmod never writes private content or changes originals."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def erlang(code, deny_mode=False):
    command = ["erl", "-noshell", "-pa", "build/dev/erlang/redirect_proxy/ebin",
               "-eval", code + ", halt()."]
    if deny_mode:
        command = ["/usr/bin/sandbox-exec", "-p",
                   "(version 1)(allow default)(deny file-write-mode)"] + command
    subprocess.run(command, check=True, timeout=30)


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
        print("permission-denial regression passed")
    finally:
        shutil.rmtree(directory)


if __name__ == "__main__":
    main()
