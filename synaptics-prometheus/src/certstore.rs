//! Where the pairing cert store lives.
//!
//! Every tool in this workspace needs the same 4 KB of pairing material, and every one of them used
//! to default to `certstore.bin` **in the current directory**. That means the file gets copied into
//! each worktree, each of those copies drifts independently, and a tool run from anywhere else fails
//! at session open for a reason that has nothing to do with the sensor.
//!
//! So there is one canonical location — `$XDG_CONFIG_HOME/synaptics-fp-re/certstore.bin`, falling
//! back to `~/.config/...` per the XDG Base Directory spec — and a search path that keeps every
//! existing invocation working:
//!
//! 1. the path the caller asked for, if it exists;
//! 2. the XDG path — but **only** if what was asked for was the bare conventional name, which is
//!    what every tool here passes when the user named nothing;
//! 3. otherwise the path the caller asked for, so the error names the file they meant.
//!
//! Rule 2's restriction is the whole difference between a search path and a silent redirect. A
//! `--certstore /tmp/typo.bin` that does not exist has to fail saying `/tmp/typo.bin`; quietly
//! opening different pairing material instead would turn a typo into a mystery.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Conventional file name, in whichever directory.
pub const FILE: &str = "certstore.bin";

/// This project's subdirectory under the XDG config root.
pub const APP_DIR: &str = "synaptics-fp-re";

/// `$XDG_CONFIG_HOME/synaptics-fp-re`, or `$HOME/.config/synaptics-fp-re`.
///
/// `None` when neither variable is set — a daemon or a build sandbox — in which case callers fall
/// back to the working directory as before.
pub fn config_dir() -> Option<PathBuf> {
    // The spec says a relative XDG_CONFIG_HOME must be ignored, not resolved against the cwd.
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join(APP_DIR))
}

/// The canonical cert-store path, whether or not anything is there yet.
///
/// This is what to print when telling somebody where to put the file.
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join(FILE))
}

/// The default for a tool that was not given a path: the XDG one if it is there, else `certstore.bin`
/// in the working directory, which is what every tool here did before.
pub fn default_path() -> PathBuf {
    match config_path() {
        Some(p) if p.is_file() => p,
        _ => PathBuf::from(FILE),
    }
}

/// Apply the search path described in the module docs to a path a caller asked for.
pub fn resolve(requested: &str) -> PathBuf {
    resolve_with(requested, config_path().as_deref(), |p| p.is_file())
}

/// [`resolve`] the path, read it, and say which file it was.
///
/// The log line is not decoration: with a search path in play, "which pairing material did this
/// run use" stops being obvious from the command line, and that is exactly the question you ask
/// when a session fails to establish.
pub fn read(requested: &str) -> std::io::Result<Vec<u8>> {
    let path = resolve(requested);
    let bytes = std::fs::read(&path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("read cert store {}: {e}", path.display()))
    })?;
    log::info!("cert store: {} ({} bytes)", path.display(), bytes.len());
    Ok(bytes)
}

/// [`resolve`] with the environment and the filesystem injected, so the policy can be tested
/// without touching either — process-wide env vars are shared mutable state, and a test that sets
/// them is a test that fights every other test in the binary.
fn resolve_with(requested: &str, config: Option<&Path>, exists: impl Fn(&Path) -> bool) -> PathBuf {
    let asked = PathBuf::from(requested);
    if exists(&asked) {
        return asked;
    }
    match config {
        // Only a bare `certstore.bin` falls through to the config copy. Anything else was a
        // deliberate choice of file and gets reported as missing rather than substituted.
        Some(c) if is_bare_default(&asked) && exists(c) => c.to_path_buf(),
        _ => asked,
    }
}

/// `certstore.bin` with no directory part — i.e. what a tool passes when nobody named a file.
///
/// `./certstore.bin` deliberately does not count: writing the directory out, even as `.`, is a
/// statement about *which* file.
fn is_bare_default(p: &Path) -> bool {
    p.file_name() == Some(OsStr::new(FILE))
        && p.parent().is_none_or(|d| d.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "/home/u/.config/synaptics-fp-re/certstore.bin";

    fn resolve_when(requested: &str, present: &[&str]) -> String {
        let present: Vec<PathBuf> = present.iter().map(PathBuf::from).collect();
        resolve_with(requested, Some(Path::new(CONFIG)), |p| present.iter().any(|q| q == p))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn a_file_that_is_there_wins() {
        // Both present: the explicit path is what the caller meant.
        assert_eq!(resolve_when("certstore.bin", &["certstore.bin", CONFIG]), "certstore.bin");
        assert_eq!(resolve_when("/tmp/mine.bin", &["/tmp/mine.bin", CONFIG]), "/tmp/mine.bin");
    }

    #[test]
    fn the_config_copy_covers_a_missing_working_directory_file() {
        assert_eq!(resolve_when("certstore.bin", &[CONFIG]), CONFIG);
    }

    /// The reason this is a search path and not a redirect.
    ///
    /// The first case is the one that matters and the one an earlier version of this got wrong: a
    /// missing explicit path fell through to the config copy, so a typo silently opened different
    /// pairing material. A test with *neither* file present passed anyway — it could not tell the
    /// two behaviours apart.
    #[test]
    fn a_named_file_that_is_missing_is_never_substituted() {
        assert_eq!(resolve_when("/tmp/typo.bin", &[CONFIG]), "/tmp/typo.bin");
        assert_eq!(resolve_when("other.bin", &[CONFIG]), "other.bin");
        // Spelling the directory out, even as `.`, is a statement about which file.
        assert_eq!(resolve_when("./certstore.bin", &[CONFIG]), "./certstore.bin");
    }

    #[test]
    fn nothing_anywhere_reports_the_path_that_was_asked_for() {
        assert_eq!(resolve_when("/tmp/typo.bin", &[]), "/tmp/typo.bin");
        assert_eq!(resolve_when("certstore.bin", &[]), "certstore.bin");
    }

    #[test]
    fn no_config_dir_at_all_degrades_to_the_old_behaviour() {
        let out = resolve_with("certstore.bin", None, |_| false);
        assert_eq!(out, PathBuf::from("certstore.bin"));
    }
}
