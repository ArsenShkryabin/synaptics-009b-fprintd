//! Template-database wire commands (`0x45`..`0x4b`): query stats/records/users, and (behind `writes`)
//! enroll / delete on **match-on-chip** SKUs (`storage_mode == 3`).
//!
//! On **EOH/MOH** SKUs (this MSI `009b` build uses `CEohMohEIV`), templates live on the **host**
//! WBF/QM store — see `docs/bringup/host-templates.md`. This module's parsers/builders remain for
//! family SKUs where the SPI template DB is active (python-validity `db.py` path).
//!
//! Wire layer (ghidra `syna_cmd_45..4b`; python-validity `db.py`). All multi-byte fields are LE.
//! Every parser takes the response payload **after** the 2-byte status word.
//!
//! ## Safety
//! The query builders (`0x45/0x46/0x49/0x4a/0x4b`) are read-only and always available. The mutating
//! builders (`0x47` new-record / `0x48` del-record) are compiled **only** with `--features writes`
//! and are how Windows Hello enrollments are created/destroyed — deleting records will break an
//! existing Hello enrollment. They are never used by the default build.

use crate::devices::FlashProfile;
use crate::error::{Error, Result};
use crate::proto::Opcode;
use crate::wire::{self, Cursor};

/// Template-DB partition capacity (`partition 3`) for a sensor [`FlashProfile`].
pub fn template_db_capacity(flash: FlashProfile) -> u32 {
    flash.template_db_size()
}

/// A DB2 object's **record type** — the node's role in the enrollment tree
/// (`StgWindsor` → users → fingers → data). Recovered from python-validity's `db.py` write paths
/// (`new_user_storate`/`new_user`/`new_finger`/`new_data`) and the DLL's `scs_cmd_db2_*` handlers.
///
/// The tree shape is: [`UserStorage`] (a named container like `StgWindsor`) → [`User`] records →
/// [`Finger`] records → [`RecordType::Data`] blobs (the per-print datum, plus the storage's machine-id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    /// `4` — a named storage container (e.g. `StgWindsor`, the Windows Hello enrollment root).
    UserStorage = 4,
    /// `5` — a user record; its identity is a Windows SID and its children are [`Finger`]s.
    User = 5,
    /// `6` — an enrolled finger. (`new_finger` submits type `0xb`; the firmware's `db_write_enable`
    /// path rewrites it to `6` on store — so it always reads back as `6`.)
    Finger = 6,
    /// `8` — an opaque "data" blob. The per-finger credential/associated data (`get_finger_blobs`
    /// filters a finger's children for this type) and the storage's machine-id record.
    Data = 8,
    /// Any type we don't have a name for yet (carries the raw value).
    Other(u16),
}

impl RecordType {
    /// The write-time type code `new_finger` submits before the firmware rewrites it to `6`.
    pub const FINGER_WRITE: u16 = 0xb;

    pub fn from_id(v: u16) -> RecordType {
        match v {
            4 => RecordType::UserStorage,
            5 => RecordType::User,
            6 => RecordType::Finger,
            8 => RecordType::Data,
            other => RecordType::Other(other),
        }
    }

    pub fn id(self) -> u16 {
        match self {
            RecordType::UserStorage => 4,
            RecordType::User => 5,
            RecordType::Finger => 6,
            RecordType::Data => 8,
            RecordType::Other(v) => v,
        }
    }

    /// Short human label for printing (`"user-storage"`, `"user"`, `"finger"`, `"data"`).
    pub fn label(self) -> &'static str {
        match self {
            RecordType::UserStorage => "user-storage",
            RecordType::User => "user",
            RecordType::Finger => "finger",
            RecordType::Data => "data",
            RecordType::Other(_) => "other",
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::Other(v) => write!(f, "other(0x{v:x})"),
            _ => write!(f, "{}", self.label()),
        }
    }
}

// ------------------------------------------------------------------- query builders

/// `0x45` db-info (bare command).
pub fn cmd_db_info() -> Vec<u8> {
    vec![Opcode::DbInfo.byte()]
}

/// `0x46` get-record-children: `46 | dbid:u16`.
pub fn cmd_get_record_children(dbid: u16) -> Vec<u8> {
    let mut c = vec![Opcode::GetRecordChildren.byte()];
    c.extend_from_slice(&dbid.to_le_bytes());
    c
}

/// `0x49` get-record-value: `49 | dbid:u16`.
pub fn cmd_get_record_value(dbid: u16) -> Vec<u8> {
    let mut c = vec![Opcode::GetRecordValue.byte()];
    c.extend_from_slice(&dbid.to_le_bytes());
    c
}

/// `0x4a` get-user: `4a | dbid:u16 | 0:u16 | 0:u16`.
pub fn cmd_get_user(dbid: u16) -> Vec<u8> {
    let mut c = vec![Opcode::GetUser.byte()];
    c.extend_from_slice(&dbid.to_le_bytes());
    c.extend_from_slice(&[0, 0, 0, 0]);
    c
}

/// `0x4b` get-user-storage by name: `4b | dbid:u16 | namelen:u16 | name(+NUL if non-empty)`.
pub fn cmd_get_user_storage(dbid: u16, name: &str) -> Vec<u8> {
    let mut nb = name.as_bytes().to_vec();
    if !nb.is_empty() {
        nb.push(0);
    }
    let mut c = vec![Opcode::GetUserStorage.byte()];
    c.extend_from_slice(&dbid.to_le_bytes());
    c.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    c.extend_from_slice(&nb);
    c
}

// ------------------------------------------------------------------- query results

/// `0x45` result. `records` includes deleted; `roots` are the top-level record ids.
#[derive(Debug, Clone)]
pub struct DbInfo {
    pub total: u32,
    pub used: u32,
    pub free: u32,
    pub records: u16,
    pub roots: Vec<u16>,
}

impl DbInfo {
    /// Minimum payload: the `<LLLLLHH>` header before the root-id table (0x18 bytes).
    const HEADER_LEN: usize = 0x18;
    /// The two leading unknown u32s (`u1`, `u0`) before the stats fields.
    const STATS_OFFSET: usize = 0x08;
    /// Each root id is a `u16`.
    const ROOT_STRIDE: usize = 2;

    /// Parse the payload after the status word. Layout `<LLLLLHH>` = u1,u0,total,used,free,records,nroots + roots.
    pub fn parse(p: &[u8]) -> Result<DbInfo> {
        if p.len() < Self::HEADER_LEN {
            return Err(Error::Malformed(format!(
                "db_info short: {} bytes",
                p.len()
            )));
        }
        let mut c = Cursor::new(p);
        c.skip(Self::STATS_OFFSET)?; // u1, u0 (unknown)
        let total = c.read_u32_le()?;
        let used = c.read_u32_le()?;
        let free = c.read_u32_le()?;
        let records = c.read_u16_le()?;
        let nroots = c.read_u16_le()? as usize;
        let roots = wire::read_records(c.take_rest(), Self::ROOT_STRIDE, nroots, |b| {
            Cursor::new(b).read_u16_le().unwrap_or_default()
        });
        Ok(DbInfo {
            total,
            used,
            free,
            records,
            roots,
        })
    }
}

/// A child entry from `0x46`.
#[derive(Debug, Clone, Copy)]
pub struct RecordChild {
    pub dbid: u16,
    pub typ: RecordType,
}

/// `0x46` result: a record header plus its children.
#[derive(Debug, Clone)]
pub struct RecordChildren {
    pub dbid: u16,
    pub typ: RecordType,
    pub storage: u16,
    pub children: Vec<RecordChild>,
}

impl RecordChildren {
    /// Minimum payload: the `<xxHHHHHxx>` header (14 bytes) before the child table.
    const HEADER_LEN: usize = 14;
    /// Each child entry is `(dbid:u16, type:u16)` = 4 bytes.
    const CHILD_STRIDE: usize = 4;

    /// Parse payload after status. Header `<xxHHHHHxx>` then `cnt` × `(dbid:u16, type:u16)`.
    pub fn parse(p: &[u8]) -> Result<RecordChildren> {
        if p.len() < Self::HEADER_LEN {
            return Err(Error::Malformed(format!(
                "children short: {} bytes",
                p.len()
            )));
        }
        let mut c = Cursor::new(p);
        c.skip(2)?; // leading xx
        let dbid = c.read_u16_le()?;
        let typ = RecordType::from_id(c.read_u16_le()?);
        let storage = c.read_u16_le()?;
        c.skip(2)?; // unknown H at offset 8
        let cnt = c.read_u16_le()? as usize;
        c.skip(2)?; // trailing xx
        let children = wire::read_records(c.take_rest(), Self::CHILD_STRIDE, cnt, |b| {
            let mut r = Cursor::new(b);
            RecordChild {
                dbid: r.read_u16_le().unwrap_or_default(),
                typ: RecordType::from_id(r.read_u16_le().unwrap_or_default()),
            }
        });
        Ok(RecordChildren {
            dbid,
            typ,
            storage,
            children,
        })
    }
}

/// `0x49` result: a record and its opaque value.
#[derive(Debug, Clone)]
pub struct RecordValue {
    pub dbid: u16,
    pub typ: RecordType,
    pub storage: u16,
    pub value: Vec<u8>,
}

impl RecordValue {
    /// Minimum payload: the `<xxHHHHxx>` header (12 bytes) before the value.
    const HEADER_LEN: usize = 12;

    /// Parse payload after status. Header `<xxHHHHxx>` (12 bytes) then `sz` value bytes.
    pub fn parse(p: &[u8]) -> Result<RecordValue> {
        if p.len() < Self::HEADER_LEN {
            return Err(Error::Malformed(format!("record short: {} bytes", p.len())));
        }
        let mut c = Cursor::new(p);
        c.skip(2)?; // leading xx
        let dbid = c.read_u16_le()?;
        let typ = RecordType::from_id(c.read_u16_le()?);
        let storage = c.read_u16_le()?;
        let sz = c.read_u16_le()? as usize;
        c.skip(2)?; // trailing xx
        let value = c.take_rest().get(..sz).unwrap_or(&[]).to_vec();
        Ok(RecordValue {
            dbid,
            typ,
            storage,
            value,
        })
    }
}

/// One enrolled finger belonging to a [`User`].
#[derive(Debug, Clone, Copy)]
pub struct Finger {
    pub dbid: u16,
    /// Windows biometric subtype (finger position). See [`finger_name`].
    pub subtype: u16,
    pub storage: u16,
    pub value_size: u16,
}

/// `0x4a` result: a user record with its fingers and raw identity (a Windows SID blob).
#[derive(Debug, Clone)]
pub struct User {
    pub dbid: u16,
    pub fingers: Vec<Finger>,
    pub identity: Vec<u8>,
}

impl User {
    /// Minimum payload: the `<HHHH>` header before the finger table.
    const HEADER_LEN: usize = 8;
    /// Each finger record is `(dbid, subtype, storage, value_size)` u16s = 8 bytes.
    const FINGER_STRIDE: usize = 8;

    /// Parse payload after status. Header `<HHHH>` = recid,fingercnt,unknown,identitysz;
    /// then `fingercnt` × 8-byte finger records; then `identitysz` identity bytes.
    pub fn parse(p: &[u8]) -> Result<User> {
        if p.len() < Self::HEADER_LEN {
            return Err(Error::Malformed(format!("user short: {} bytes", p.len())));
        }
        let mut c = Cursor::new(p);
        let recid = c.read_u16_le()?;
        let fingercnt = c.read_u16_le()? as usize;
        c.skip(2)?; // unknown
        let identitysz = c.read_u16_le()? as usize;
        // The finger table has a fixed footprint (`8 * fingercnt`) after which the identity blob
        // begins, whether or not every finger record is actually present in a truncated reply.
        let rest = c.take_rest();
        let ftab_len = Self::FINGER_STRIDE * fingercnt;
        let ftab = rest.get(..ftab_len).unwrap_or(&[]);
        let identity = rest
            .get(ftab_len..ftab_len + identitysz)
            .unwrap_or(&[])
            .to_vec();
        let fingers = wire::read_records(ftab, Self::FINGER_STRIDE, fingercnt, |b| {
            let mut r = Cursor::new(b);
            Finger {
                dbid: r.read_u16_le().unwrap_or_default(),
                subtype: r.read_u16_le().unwrap_or_default(),
                storage: r.read_u16_le().unwrap_or_default(),
                value_size: r.read_u16_le().unwrap_or_default(),
            }
        });
        Ok(User {
            dbid: recid,
            fingers,
            identity,
        })
    }
}

/// One user entry within a [`UserStorage`].
#[derive(Debug, Clone, Copy)]
pub struct StorageUser {
    pub dbid: u16,
    pub value_size: u16,
}

/// `0x4b` result: a named storage container and the users in it. `None` maps to status `0x04b3`.
#[derive(Debug, Clone)]
pub struct UserStorage {
    pub dbid: u16,
    pub name: Vec<u8>,
    pub users: Vec<StorageUser>,
}

impl UserStorage {
    /// Minimum payload: the `<HHHH>` header before the user table.
    const HEADER_LEN: usize = 8;
    /// Each user record is `(dbid, value_size)` u16s = 4 bytes.
    const USER_STRIDE: usize = 4;

    /// Parse payload after status. Header `<HHHH>` = recid,usercnt,namesz,unknown; then
    /// `usercnt` × 4-byte user records; then `namesz` name bytes.
    pub fn parse(p: &[u8]) -> Result<UserStorage> {
        if p.len() < Self::HEADER_LEN {
            return Err(Error::Malformed(format!(
                "storage short: {} bytes",
                p.len()
            )));
        }
        let mut c = Cursor::new(p);
        let recid = c.read_u16_le()?;
        let usercnt = c.read_u16_le()? as usize;
        let namesz = c.read_u16_le()? as usize;
        c.skip(2)?; // unknown
        // The user table has a fixed footprint (`4 * usercnt`) after which the name blob begins.
        let rest = c.take_rest();
        let utab_len = Self::USER_STRIDE * usercnt;
        let utab = rest.get(..utab_len).unwrap_or(&[]);
        let name = rest
            .get(utab_len..utab_len + namesz)
            .unwrap_or(&[])
            .to_vec();
        let users = wire::read_records(utab, Self::USER_STRIDE, usercnt, |b| {
            let mut r = Cursor::new(b);
            StorageUser {
                dbid: r.read_u16_le().unwrap_or_default(),
                value_size: r.read_u16_le().unwrap_or_default(),
            }
        });
        Ok(UserStorage {
            dbid: recid,
            name,
            users,
        })
    }
}

/// Human-readable name for a Windows biometric finger subtype (WinBio `*_POSITION`).
pub fn finger_name(subtype: u16) -> &'static str {
    match subtype {
        0x00 => "unknown/any",
        0x01 => "right thumb",
        0x02 => "right index",
        0x03 => "right middle",
        0x04 => "right ring",
        0x05 => "right little",
        0x06 => "left thumb",
        0x07 => "left index",
        0x08 => "left middle",
        0x09 => "left ring",
        0x0a => "left little",
        0xf5 => "swipe",
        _ => "other",
    }
}

// -------------------------------------------------- mutating builders (writes feature)

/// Destructive template-DB command builders. **Compiled only with `--features writes`.**
///
/// These change persistent sensor state and are how Windows Hello enrollments are made and removed.
/// `cmd_del_record` on a Hello-owned record destroys that enrollment; `cmd_new_record` is the
/// enroll write. The crate never calls these in the default build; a caller that enables `writes`
/// is asserting it intends to modify enrollments.
#[cfg(feature = "writes")]
pub mod writes {
    use crate::proto::Opcode;
    /// `0x48` delete-record: `48 | dbid:u16`. **Destroys the record (and any Hello enrollment).**
    pub fn cmd_del_record(dbid: u16) -> Vec<u8> {
        let mut c = vec![Opcode::DelRecord.byte()];
        c.extend_from_slice(&dbid.to_le_bytes());
        c
    }

    /// `0x47` new-record: `47 | parent:u16 | type:u16 | storage:u16 | len:u16 | data`.
    /// Must be preceded by the `db_write_enable` unlock. Creates a template/user/finger record.
    pub fn cmd_new_record(parent: u16, typ: u16, storage: u16, data: &[u8]) -> Vec<u8> {
        let mut c = vec![Opcode::NewRecord.byte()];
        c.extend_from_slice(&parent.to_le_bytes());
        c.extend_from_slice(&typ.to_le_bytes());
        c.extend_from_slice(&storage.to_le_bytes());
        c.extend_from_slice(&(data.len() as u16).to_le_bytes());
        c.extend_from_slice(data);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_db_capacity_matches_flash_profile() {
        use crate::devices::FlashProfile;
        assert_eq!(template_db_capacity(FlashProfile::Large), 0x0008_0000);
        assert_eq!(template_db_capacity(FlashProfile::Small), 0x0003_0000);
    }

    #[test]
    fn record_type_names_and_roundtrips() {
        for (id, rt, label) in [
            (4u16, RecordType::UserStorage, "user-storage"),
            (5, RecordType::User, "user"),
            (6, RecordType::Finger, "finger"),
            (8, RecordType::Data, "data"),
        ] {
            assert_eq!(RecordType::from_id(id), rt);
            assert_eq!(rt.id(), id);
            assert_eq!(rt.label(), label);
        }
        // Finger is submitted as 0xb but stored/read back as 6; an unknown id round-trips as Other.
        assert_eq!(RecordType::FINGER_WRITE, 0xb);
        assert_eq!(RecordType::from_id(0xb), RecordType::Other(0xb));
        assert_eq!(RecordType::from_id(0xb).id(), 0xb);
        assert_eq!(format!("{}", RecordType::Other(0xb)), "other(0xb)");
    }

    #[test]
    fn db_info_parses_stats_and_roots() {
        // u1=1,u0=0,total=0x1000,used=0x40,free=0xfc0,records=3,nroots=2, roots=[3,5]
        let mut p = Vec::new();
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&0x1000u32.to_le_bytes());
        p.extend_from_slice(&0x40u32.to_le_bytes());
        p.extend_from_slice(&0xfc0u32.to_le_bytes());
        p.extend_from_slice(&3u16.to_le_bytes());
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&3u16.to_le_bytes());
        p.extend_from_slice(&5u16.to_le_bytes());
        let info = DbInfo::parse(&p).unwrap();
        assert_eq!(
            (info.total, info.used, info.free, info.records),
            (0x1000, 0x40, 0xfc0, 3)
        );
        assert_eq!(info.roots, vec![3, 5]);
    }

    #[test]
    fn user_parses_fingers() {
        // hdr: recid=7, fingercnt=1, unknown=0, identitysz=4; finger(dbid=9,subtype=2,storage=3,vsz=0x30); identity=DEAD
        let mut p = Vec::new();
        p.extend_from_slice(&7u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        for v in [9u16, 2, 3, 0x30] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let u = User::parse(&p).unwrap();
        assert_eq!(u.dbid, 7);
        assert_eq!(u.fingers.len(), 1);
        assert_eq!(u.fingers[0].subtype, 2);
        assert_eq!(finger_name(u.fingers[0].subtype), "right index");
        assert_eq!(u.identity, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn builders_frame_correctly() {
        assert_eq!(cmd_db_info(), vec![0x45]); // ground-truth wire byte
        assert_eq!(cmd_get_user(0x1234), vec![0x4a, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(cmd_get_record_children(7), vec![0x46, 7, 0]);
        assert_eq!(cmd_get_user_storage(0, "StgWindsor")[..3], [0x4b, 0, 0]);
    }
}
