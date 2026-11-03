//! Opaque host-side enrolled-template store, keyed by `(user id, finger subtype)`.
//!
//! Persists the backend's multi-view enrolled blob (from
//! [`crate::host_biometric::EnrollSession::finalize`]) on disk. Layout: `<root>/<user>/<subtype>.tmpl`,
//! each file a small header + the opaque blob. Keying mirrors the on-sensor DB2 model (user → finger by
//! WinBio subtype `0x01..0x0a`, see [`crate::db::finger_name`]).
//!
//! This is **not** the Windows WBF `.DAT` / DPAPI format — it is a Linux-native store (that format is
//! Windows-specific and out of scope). Blobs are stored as-is (no encryption); treat the store dir as
//! sensitive (it holds biometric templates).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// File magic + version for a stored template.
const MAGIC: &[u8; 4] = b"SPTS";
const VERSION: u8 = 1;
/// Header length: magic(4) + version(1) + subtype(1) + pad(2) + user(4) + created(8) + blob_len(4).
const HEADER_LEN: usize = 24;

/// A stored enrolled template with its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTemplate {
    pub user: u32,
    pub subtype: u8,
    /// Unix seconds when stored.
    pub created_unix: u64,
    /// The opaque multi-view enrolled blob.
    pub blob: Vec<u8>,
}

/// An on-disk template store rooted at a directory.
#[derive(Debug, Clone)]
pub struct TemplateStore {
    root: PathBuf,
}

impl TemplateStore {
    /// Open (creating if needed) a store at `root`.
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn finger_path(&self, user: u32, subtype: u8) -> PathBuf {
        self.root.join(user.to_string()).join(format!("{subtype:02x}.tmpl"))
    }

    /// Store (overwriting) the enrolled `blob` for `(user, subtype)`.
    pub fn store(&self, user: u32, subtype: u8, blob: &[u8]) -> io::Result<()> {
        let created = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut out = Vec::with_capacity(HEADER_LEN + blob.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(subtype);
        out.extend_from_slice(&[0u8, 0u8]); // pad
        out.extend_from_slice(&user.to_le_bytes());
        out.extend_from_slice(&created.to_le_bytes());
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        out.extend_from_slice(blob);
        let path = self.finger_path(user, subtype);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // write to a temp file then rename for atomicity
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, &path)
    }

    /// Load the stored template for `(user, subtype)`, or `None` if absent.
    pub fn load(&self, user: u32, subtype: u8) -> io::Result<Option<StoredTemplate>> {
        let path = self.finger_path(user, subtype);
        let raw = match fs::read(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Self::decode(&raw).map(Some)
    }

    /// Convenience: just the blob for `(user, subtype)`.
    pub fn load_blob(&self, user: u32, subtype: u8) -> io::Result<Option<Vec<u8>>> {
        Ok(self.load(user, subtype)?.map(|t| t.blob))
    }

    fn decode(raw: &[u8]) -> io::Result<StoredTemplate> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
        if raw.len() < HEADER_LEN || &raw[0..4] != MAGIC {
            return Err(bad("not a template file"));
        }
        if raw[4] != VERSION {
            return Err(bad("unsupported template version"));
        }
        let subtype = raw[5];
        let user = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let created_unix = u64::from_le_bytes(raw[12..20].try_into().unwrap());
        let blob_len = u32::from_le_bytes(raw[20..24].try_into().unwrap()) as usize;
        let blob = raw.get(HEADER_LEN..HEADER_LEN + blob_len).ok_or_else(|| bad("truncated blob"))?;
        Ok(StoredTemplate { user, subtype, created_unix, blob: blob.to_vec() })
    }

    /// Enrolled finger subtypes for `user`, sorted ascending.
    pub fn list_fingers(&self, user: u32) -> io::Result<Vec<u8>> {
        let dir = self.root.join(user.to_string());
        let mut out = Vec::new();
        match fs::read_dir(&dir) {
            Ok(entries) => {
                for e in entries {
                    let name = e?.file_name();
                    if let Some(s) = name.to_str().and_then(|n| n.strip_suffix(".tmpl"))
                        && let Ok(subtype) = u8::from_str_radix(s, 16)
                    {
                        out.push(subtype);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        out.sort_unstable();
        Ok(out)
    }

    /// All user ids with at least one enrolled finger, sorted ascending.
    pub fn users(&self) -> io::Result<Vec<u32>> {
        let mut out = Vec::new();
        for e in fs::read_dir(&self.root)? {
            let name = e?.file_name();
            if let Some(u) = name.to_str().and_then(|n| n.parse::<u32>().ok()) {
                out.push(u);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Delete the template for `(user, subtype)`; returns whether it existed.
    pub fn delete(&self, user: u32, subtype: u8) -> io::Result<bool> {
        match fs::remove_file(self.finger_path(user, subtype)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("spts_{}_{}", std::process::id(), tag))
    }

    #[test]
    fn store_load_list_delete_roundtrip() {
        let root = temp_root("rt");
        let _ = fs::remove_dir_all(&root);
        let store = TemplateStore::open(&root).unwrap();

        assert!(store.load(1, 0x05).unwrap().is_none());
        store.store(1, 0x05, b"multiview-blob-A").unwrap();
        store.store(1, 0x08, b"multiview-blob-B").unwrap();
        store.store(2, 0x01, b"blob-C").unwrap();

        let got = store.load(1, 0x05).unwrap().unwrap();
        assert_eq!(got.user, 1);
        assert_eq!(got.subtype, 0x05);
        assert_eq!(got.blob, b"multiview-blob-A");

        assert_eq!(store.list_fingers(1).unwrap(), vec![0x05, 0x08]);
        assert_eq!(store.users().unwrap(), vec![1, 2]);

        assert!(store.delete(1, 0x05).unwrap());
        assert!(!store.delete(1, 0x05).unwrap());
        assert_eq!(store.list_fingers(1).unwrap(), vec![0x08]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_non_template_file() {
        let root = temp_root("bad");
        let _ = fs::remove_dir_all(&root);
        let store = TemplateStore::open(&root).unwrap();
        let path = store.finger_path(1, 0x05);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"garbage").unwrap();
        assert!(store.load(1, 0x05).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
