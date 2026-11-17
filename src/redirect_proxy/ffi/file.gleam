//// Bindings to `redirect_proxy_file_ffi`: atomic writes, file stamps, the
//// node-wide and cross-process locks, and the delays tests shorten.

/// Creates the table of `memo_file` in the calling process, which owns it
/// (`tables`). Without it (a command), nothing is cached.
@external(erlang, "redirect_proxy_file_ffi", "memo_init")
pub fn memo_init() -> Nil

/// `compute()` for a file, cached until the file is written again. On an
/// error, the last successful value is returned when there is one.
@external(erlang, "redirect_proxy_file_ffi", "memo_file")
pub fn memo_file(path: String, compute: fn() -> Result(a, e)) -> Result(a, e)

/// Exclusively creates, closes and removes an empty probe. Existing paths
/// are never modified or removed.
@external(erlang, "redirect_proxy_file_ffi", "probe_writable_file")
pub fn probe_writable_file(path: String) -> Result(Nil, String)

@external(erlang, "redirect_proxy_file_ffi", "atomic_write")
pub fn atomic_write(path: String, content: String) -> Result(Nil, String)

/// `atomic_write` for files holding secrets: a new file is created 0600
/// (an existing one keeps its permissions, but for those of others).
@external(erlang, "redirect_proxy_file_ffi", "atomic_write_private")
pub fn atomic_write_private(
  path: String,
  content: String,
) -> Result(Nil, String)

/// Rotates a full audit log after preparing its replacement with the
/// original permissions. On success the new active file holds only `line`.
@external(erlang, "redirect_proxy_file_ffi", "audit_rotate")
pub fn audit_rotate(
  path: String,
  line: String,
  mode: Int,
  keep: Int,
) -> Result(Nil, String)

/// Copies `source` to a new file `dest` created with the permissions of
/// `source` (never more readable, not even while it is written).
@external(erlang, "redirect_proxy_file_ffi", "copy_file_as")
pub fn copy_file_as(source: String, dest: String) -> Result(Nil, String)

@external(erlang, "redirect_proxy_file_ffi", "append_line")
pub fn append_line(path: String, line: String) -> Result(Nil, String)

/// The owner of `dir` when this OS process runs as root and `dir` belongs
/// to another user (CLI commands would create root-owned files there).
@external(erlang, "redirect_proxy_file_ffi", "data_dir_owner_mismatch")
pub fn data_dir_owner_mismatch(dir: String) -> Result(String, Nil)

// --- stamps -----------------------------------------------------------------

/// Identifies a version of a file on disk: its inode, modification time and
/// size. Two equal stamps mean the file was very probably not changed.
pub type FileStamp

@external(erlang, "redirect_proxy_file_ffi", "file_stamp")
pub fn file_stamp(path: String) -> FileStamp

/// Whether the file was modified within the last two seconds: a stamp that
/// did not change may then still hide a change of the same size.
@external(erlang, "redirect_proxy_file_ffi", "stamp_is_recent")
pub fn stamp_is_recent(stamp: FileStamp) -> Bool

/// Whether stamp `b` may be of the write of stamp `a`: the same file and
/// size, its time moved forward by a second at most (a write in place may
/// set it again after the content). Times have a one second resolution:
/// the same content written again within that second is not told apart.
@external(erlang, "redirect_proxy_file_ffi", "same_write")
pub fn same_write(a: FileStamp, b: FileStamp) -> Bool

// --- locks ------------------------------------------------------------------

/// Runs `f` while holding a node-wide lock named `name`.
@external(erlang, "redirect_proxy_file_ffi", "with_lock")
pub fn with_lock(name: String, f: fn() -> a) -> a

/// Runs `f` holding `<path>.lock`, an exclusive lock shared by every OS
/// process writing `path` (the server, the CLI). The lock is refreshed while
/// `f` runs; one not refreshed for 10 seconds is left over by a crashed
/// process and is taken over. Errors when the lock is not acquired in time.
@external(erlang, "redirect_proxy_file_ffi", "with_file_lock")
pub fn with_file_lock(
  path: String,
  timeout_ms: Int,
  f: fn() -> a,
) -> Result(a, String)

/// Why `with_file_lock_detailed` did not acquire the lock.
pub type LockFailure {
  /// Another process holds it: trying again soon may succeed.
  Held(message: String)
  /// It could not be created (a full disk).
  CannotCreate(message: String)
}

/// `with_file_lock`, saying why the lock was not acquired.
@external(erlang, "redirect_proxy_file_ffi", "with_file_lock_detailed")
pub fn with_file_lock_detailed(
  path: String,
  timeout_ms: Int,
  f: fn() -> a,
) -> Result(a, LockFailure)

/// Read-modify-write of a data file that other OS processes (the CLI) may
/// write too: holds the node-wide lock of `path`, then `<path>.lock`, for up
/// to `timeout_ms`.
pub fn locked_file(
  path: String,
  timeout_ms: Int,
  f: fn() -> Result(a, String),
) -> Result(a, String) {
  use <- with_lock(path)
  case with_file_lock(path, timeout_ms, f) {
    Ok(result) -> result
    Error(reason) -> Error(reason)
  }
}

/// A delay's override (tests shorten some, see `support.set_tunable`), or
/// `default`.
@external(erlang, "redirect_proxy_file_ffi", "tunable")
pub fn tunable(name: String, default: Int) -> Int
